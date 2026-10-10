"""RDL section queries remain scoped to one scan and recorded evidence."""
import json
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from . import main
from .models import ScanRun


class RdlReviewSectionTests(TestCase):
    def test_endpoint_filters_before_paging_and_preserves_query(self):
        record = dict(v2_rule_id='command', v2_outcome='MATCH', v1_outcome='NO_MATCH', status='DISAGREEMENT',
                      context={'file_path':'entry.py'}, v2_findings=[dict(title='Command', evidence=[
                          dict(predicate='SOURCE', matched=True, location={'path':'entry.py','line':1}),
                          dict(predicate='SINK', matched=True, location={'path':'runner.py','line':8})])])
        with TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'runtime').mkdir()
            (root/'runtime/rdl_shadow_comparisons.jsonl').write_text(json.dumps(record)+'\n')
            db = Mock()
            db.query.return_value.filter.return_value.first.return_value = ScanRun(run_uuid='recorded',status='success',rdl_engine='both')
            with patch.object(main, 'run_dir', return_value=root):
                result = main.get_rdl_shadow_results('recorded',limit=1,offset=0,view='leads',kind='all',section='xref',search='',db=db)
            self.assertTrue(result['enabled'])
            self.assertEqual(1,result['section_counts']['xref'])
            self.assertEqual(1,result['filtered_total'])
            self.assertEqual('xref',result['query']['section'])
            self.assertEqual(['SOURCE','SINK'],[step['predicate'] for step in result['comparisons'][0]['v2_findings'][0]['trace']['steps']])

    def test_removed_scan_does_not_read_evidence(self):
        db=Mock()
        db.query.return_value.filter.return_value.first.return_value=ScanRun(run_uuid='removed',status='success',data_removed_at=datetime.now())
        with patch.object(main,'run_dir') as run_dir:
            result=main.get_rdl_shadow_results('removed',limit=1,offset=0,view='leads',kind='all',section='taint',search='',db=db)
        run_dir.assert_not_called()
        self.assertTrue(result['data_removed'])
        self.assertEqual([],result['comparisons'])
