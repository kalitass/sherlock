import json
from types import SimpleNamespace

from core.evidence_ledger import EvidenceLedger
from components.hunt import heuristic, llm_hunt


class Client:
    def list_tools(self):
        return [SimpleNamespace(name='count_logs', description='count', input_schema={})]

    def call(self, name, args):
        if name == 'list_log_types':
            return {'ok': True, 'log_types': []}
        return {'ok': True, 'matched_documents': 1}


def invoke(fn, *args):
    try:
        return fn(*args)
    except NotImplementedError:
        raise AssertionError('P4 entry point is not implemented') from None


def test_llm_hunt_records_query_and_returns_parsed_result(monkeypatch):
    class LLM:
        model = 'test-model'
        def agent_loop(self, system, user, tools, on_event):
            assert 'account' in user
            result = tools[0].fn({'query_string': 'event_id:4720'})
            return json.dumps({'verdict': 'confirmed', 'findings': [{'claim': 'account', 'evidence_ids': [result['evidence_id']]}]})
    monkeypatch.setattr(llm_hunt, 'LLMClient', LLM)
    ledger = EvidenceLedger('test', persist=False)
    result = invoke(llm_hunt.run_llm_hunt, 'account', Client(), ledger)
    assert result['engine'] == 'llm:test-model'
    assert result['findings'][0]['evidence_ids'] == ['E1']
    assert ledger.entries[0].matched_documents == 1


def test_scan_composes_scenarios_and_keeps_query_failures_incomplete(monkeypatch):
    def probe(pid, fail=False):
        def run(client, ledger):
            ev = ledger.record('count_logs', {}, {'ok': not fail, 'matched_documents': 1 if not fail else None})
            return (None, False, None) if fail else ({'claim': pid, 'evidence_ids': [ev.evidence_id], 'technique': pid, 'severity': 'high', 'role': 'positive'}, True, None)
        return heuristic.Probe(pid, pid, 'T1', pid, 'high', run)
    monkeypatch.setattr(heuristic, 'PROBES', [probe('a'), probe('b'), probe('c', True)])
    monkeypatch.setattr(heuristic, 'SCENARIOS', [heuristic.Scenario('s', 'test', [heuristic.Stage('a', 'one'), heuristic.Stage('b', 'two')])])
    ledger = EvidenceLedger('test', persist=False)
    result = invoke(heuristic.run_heuristic_hunt, 'question', Client(), ledger)
    assert result['verdict'] == 'confirmed'
    assert result['coverage']['probe_errors'] == 1
    assert len(result['findings']) == 3
    assert set(result['findings'][-1]['evidence_ids']) == {'E2', 'E3'}
    assert result['hypothesis_covered'] is False


def test_scan_failed_or_empty_probes_are_inconclusive(monkeypatch):
    monkeypatch.setattr(heuristic, 'PROBES', [])
    result = invoke(heuristic.run_heuristic_hunt, 'question', Client(), EvidenceLedger('test', persist=False))
    assert result['verdict'] == 'inconclusive'
