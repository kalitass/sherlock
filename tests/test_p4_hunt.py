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


def test_scan_with_no_hits_does_not_refute_any_hypothesis(monkeypatch):
    p = heuristic.Probe('quiet', 'quiet', 'T1', 'quiet', 'low', lambda c, l: (None, True, None))
    monkeypatch.setattr(heuristic, 'PROBES', [p])
    monkeypatch.setattr(heuristic, 'SCENARIOS', [])
    result = heuristic.run_heuristic_hunt('question', Client(), EvidenceLedger('test', persist=False))
    assert result['verdict'] == 'inconclusive'


def test_scenario_does_not_assert_uncorrelated_stages_form_an_attack_chain():
    scenario = heuristic.Scenario('s', 'test', [heuristic.Stage('a', 'one'), heuristic.Stage('b', 'two')])
    findings = [({'technique': 'a', 'severity': 'high', 'evidence_ids': ['E1']}), ({'technique': 'b', 'severity': 'high', 'evidence_ids': ['E2']})]
    result = heuristic._scenario_finding(scenario, list(zip(scenario.stages, findings)))
    assert 'not correlated' in result['claim'].lower()
    assert 'kill-chain:' not in result['claim'].lower()


def test_llm_malformed_structured_fields_return_inconclusive(monkeypatch):
    class LLM:
        model = 'test-model'
        def agent_loop(self, *args, **kwargs):
            return json.dumps({'verdict': 'confirmed', 'findings': 3})
    monkeypatch.setattr(llm_hunt, 'LLMClient', LLM)
    result = llm_hunt.run_llm_hunt('account', Client(), EvidenceLedger('test', persist=False))
    assert result['verdict'] == 'inconclusive'
    assert result['findings'] == []


def test_llm_failed_tool_call_is_recorded(monkeypatch):
    class FailingClient(Client):
        def call(self, name, args):
            raise RuntimeError('unavailable')
    class LLM:
        model = 'test-model'
        def agent_loop(self, system, user, tools, on_event):
            assert tools[0].fn({})['ok'] is False
            return 'not json'
    monkeypatch.setattr(llm_hunt, 'LLMClient', LLM)
    ledger = EvidenceLedger('test', persist=False)
    result = llm_hunt.run_llm_hunt('account', FailingClient(), ledger)
    assert result['verdict'] == 'inconclusive'
    assert ledger.entries[0].ok is False


def test_mordor_source_is_scanned_with_raw_fields_and_evidence(monkeypatch):
    monkeypatch.setattr(heuristic, 'PROBES', [])
    monkeypatch.setattr(heuristic, 'SCENARIOS', [])
    class MordorClient(Client):
        def call(self, name, args):
            if name == 'list_log_types':
                return {'ok': True, 'log_types': [{'index': 'sherlock-logs-mordor_adduser', 'log_type': 'mordor_adduser', 'count': 1}]}
            if name == 'get_field_mapping':
                return {'ok': True, 'fields': {'EventID': 'long'}}
            assert args['index'] == 'sherlock-logs-mordor_adduser'
            return {'ok': True, 'matched_documents': 1 if args['query_string'] == 'EventID:4720' else 0}
    ledger = EvidenceLedger('test', persist=False)
    result = heuristic.run_heuristic_hunt('account', MordorClient(), ledger)
    hits = [f for f in result['findings'] if f.get('probe') == 'mordor_account_creation']
    assert len(hits) == 1
    assert ledger.get(hits[0]['evidence_ids'][0]).matched_documents == 1
    assert result['hypothesis_covered'] is False


def test_absent_mordor_source_does_not_run_mordor_probes(monkeypatch):
    monkeypatch.setattr(heuristic, 'PROBES', [])
    monkeypatch.setattr(heuristic, 'SCENARIOS', [])
    class EmptyClient(Client):
        def call(self, name, args):
            assert name == 'list_log_types'
            return {'ok': True, 'log_types': []}
    result = heuristic.run_heuristic_hunt('question', EmptyClient(), EvidenceLedger('test', persist=False))
    assert result['coverage']['probes_run'] == 0


def test_scoped_mordor_skips_unavailable_legacy_indices(monkeypatch):
    legacy = heuristic.Probe('legacy', 'legacy', 'T', 'legacy', 'high', lambda c, l: (_ for _ in ()).throw(AssertionError('should not run')))
    monkeypatch.setattr(heuristic, 'PROBES', [legacy])
    monkeypatch.setattr(heuristic, 'SCENARIOS', [])
    monkeypatch.setattr(heuristic, '_LEGACY_INDEX', {'legacy': heuristic.WIN})
    class MordorClient(Client):
        def call(self, name, args):
            if name == 'list_log_types':
                return {'ok': True, 'log_types': [{'index': 'sherlock-logs-mordor_adduser', 'log_type': 'mordor_adduser', 'count': 1}]}
            if name == 'get_field_mapping':
                return {'ok': True, 'fields': {'EventID': 'long'}}
            return {'ok': True, 'matched_documents': 0}
    result = heuristic.run_heuristic_hunt('question', MordorClient(), EvidenceLedger('test', persist=False))
    assert result['coverage']['probe_errors'] == 0
    assert result['coverage']['probes_skipped'] == 1
