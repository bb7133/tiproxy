# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reject status cadence errors against independently written boundary scenarios."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


fixture=module('status_cadence_smoke')
helpers=module('test_cadence')
deriver=helpers.derive


class StatusCadenceTests(unittest.TestCase):
    def setUp(self):
        self.trace=fixture.make_trace()
        self.rows=helpers.written_rows(self.trace)

    def test_full_public_scenario(self):
        deriver._RUNNER.validate(self.trace)
        trace,requires=deriver.derive(self.trace,self.rows,None)
        self.assertEqual(requires,[])
        self.assertEqual(deriver.compare_with_reference(trace,self.trace,requires),([],[]))
        deriver._RUNNER.compare(trace,self.rows,self.rows)

    def test_missing_status_moves_and_early_deadlines_are_refused(self):
        for index,event in enumerate(self.trace['events']):
            if event['op']!='tick' or not event['expect']['effects']:
                continue
            rows=copy.deepcopy(self.rows);rows[index]['effects']=[]
            with self.subTest(seq=index),self.assertRaisesRegex(deriver.Refuse,'connection cadence'):
                deriver.derive(self.trace,rows,None)
            if index>0 and self.trace['events'][index-1]['op']=='tick' and not self.rows[index-1]['effects']:
                rows=copy.deepcopy(self.rows);rows[index-1]['effects']=copy.deepcopy(self.rows[index]['effects'])
                with self.subTest(early=index-1),self.assertRaises(deriver.Refuse):
                    deriver.derive(self.trace,rows,None)

    def test_status_expiry_changes_rate_without_copying_outputs(self):
        trace=copy.deepcopy(self.trace)
        # Expiring at equality would retain the first-phase written effects but
        # contradict the second phase's slower required cadence.
        start=next(i for i,e in enumerate(trace['events']) if e.get('session')=='expired-query' and e['op']=='open')
        for event in trace['events'][start:]:
            if event['at_nanos']>=200_000_000_000:
                break
            event['at_nanos']-=1
        with self.assertRaisesRegex(deriver.Refuse,'connection cadence'):
            deriver.derive(trace,self.rows,None)

    def test_unsupported_factor_history_remains_unqualified(self):
        state=deriver.State({'policy':'resource','selection':'random','rule':''})
        state.apply_config('[balance]\npolicy="connection"\n')
        state.apply_health([{'address':'a'},{'address':'b'}])
        s=deriver.Session('s',{});s.assigned=frozenset(['default/a']);state.sessions['s']=s
        state.apply_health([{'address':'a','healthy':False},{'address':'b'}])
        self.assertIsNone(deriver.derive_connection_redirects(state,set()))


if __name__=='__main__':
    unittest.main()
