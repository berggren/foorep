import unittest
import pymongo
from foorep import Repository
import uuid

class FoorepTest(unittest.TestCase):
    def setUp(self):
        """ Setup some initial configuration, and initiate a foorep repo object """
        self.dbname = uuid.uuid4().hex
        self.repo = Repository(database=self.dbname)

    def test_insert(self):
        """Add file to repository, check if return a dict """
        self.assertIsInstance(self.repo.insert(__file__), dict)

    def test_list(self):
        """List samples in repository"""
        self.assertIsInstance(self.repo.list(), pymongo.cursor.Cursor)
    
    def tearDown(self):
        c = pymongo.Connection()
        c.drop_database(self.dbname)

if __name__ == '__main__':
    unittest.main()
