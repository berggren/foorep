import unittest
import pymongo
from foorep import Repository
import uuid


class RepositoryTest(unittest.TestCase):
    def setUp(self):
        """ Setup some initial configuration, and initiate a foorep repo object """
        self.dbname = uuid.uuid4().hex
        self.repo = Repository(database=self.dbname)

    def test_insert(self):
        """Add file to repository, check if return a dict """
        self.assertIsInstance(self.repo.insert(__file__), dict)

    def test_remove(self):
        """Remove file from repository"""
        doc = self.repo.insert(__file__)
        self.assertTrue(self.repo.remove(doc['uuid']))

    def test_annotate(self):
        """Add annotation to file"""
        annotation = {
                    "type": "test",
                    "data": "test"
                }
        doc = self.repo.insert(__file__)
        self.assertTrue(self.repo.annotate(doc['uuid'], annotation))

    def test_get(self):
        """Get file from repository"""
        doc = self.repo.insert(__file__)
        self.assertIsInstance(self.repo.get(doc['uuid']), dict)

    def test_get_file(self):
        """Download file from gridFS"""
        doc = self.repo.insert(__file__)
        file = self.repo.get_file(doc['file'])
        file.read()

    def test_search(self):
        """Search for file in repository"""
        doc = self.repo.insert(__file__)
        self.assertIsInstance(self.repo.search(doc['meta']['hash']['sha1']), list)

    def test_list(self):
        """List samples in repository"""
        self.assertIsInstance(self.repo.list(), pymongo.cursor.Cursor)
    
    def tearDown(self):
        c = pymongo.Connection()
        c.drop_database(self.dbname)

if __name__ == '__main__':
    unittest.main()
