# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

"""
foorep is a forensic repository
"""


import foorep
from bson import json_util
import argparse
import json

def main():
    """
    The main entry point for the foorep cli tool
    """
    def add(args, repo):
        try:
            doc = repo.insert(args.path)
        except IOError:
            print('File not found')
            return
        if args.verbose:
            print('%s added to repository with id %s' %
                    (doc['meta']['filename'], doc['uuid']))
        return

    def remove(args, repo):
        result = repo.remove(args.uuid)
        if not result:
            print('No such file in the repository')
        return

    def search(args, repo):
        for sample in repo.search(args.hash):
            print sample['created'].strftime('%Y-%m-%d %H:%M:%S'), sample['uuid'], sample['meta']['filename']
        return

    def dump(args, repo):
        doc = repo.get(args.uuid)
        if not doc:
            print('No such file in the repository')
        else:
            print(json.dumps(doc, indent=1, default=json_util.default))
        return

    def annotate(args, repo):
        annotation = {"type": args.type, "data":args.message}
        repo.annotate(args.uuid, annotation)
        return

    def list(args, repo):
        if args.limit:
            limit = int(args.limit)
        else:
            limit = 10
        for sample in repo.list(limit=limit):
            print sample['created'].strftime('%Y-%m-%d %H:%M:%S'), sample['uuid'], sample['meta']['filename'] 

    repo = foorep.Repository()
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    subparsers = parser.add_subparsers(dest='command', title='Commands',
            description='These are the commands that I know of..')
    parser_add = subparsers.add_parser('add', help='Add sample to repository')
    parser_add.add_argument('path', help='Path to file')
    parser_add.set_defaults(func=add)
    parser_remove = subparsers.add_parser('remove', help='Remove sample from repository')
    parser_remove.add_argument('uuid', help='File to remove from the repository')
    parser_remove.set_defaults(func=remove)
    parser_search = subparsers.add_parser('search', help='Search for sample in repository')
    parser_search.add_argument('hash', help='Hash to search for')
    parser_search.set_defaults(func=search)
    parser_dump = subparsers.add_parser('dump', help='Dump raw JSON document for sample')
    parser_dump.add_argument('uuid', help='File to dump')
    parser_dump.set_defaults(func=dump)
    parser_annotate = subparsers.add_parser('annotate', help='Add annotation to sample')    
    parser_annotate.add_argument('uuid', help='File to annotate')
    parser_annotate.add_argument('-t', '--type', metavar='TYPE', help='Type of annotation')
    parser_annotate.add_argument('-m', '--message', metavar='VALUE', help='The content of the annotation')
    parser_annotate.set_defaults(func=annotate)
    parser_list = subparsers.add_parser('list', help='List sample in repository')
    parser_list.add_argument('-l', '--limit', help='Limit amount of records returned, default is 10')
    parser_list.set_defaults(func=list)
    args = parser.parse_args()
    args.func(args, repo)

if __name__ == '__main__':
    main()
