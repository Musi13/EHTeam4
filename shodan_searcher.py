import shodan
import argparse
import sys

parser = argparse.ArgumentParser(description='Search shodan for hosts vulnerable to EternalBlue')
parser.add_argument('queries', nargs='*', help='additional search queries')
parser.add_argument('--limit', help='maximum number of matching results to write to output, default being 500')
parser.add_argument('--output', help='file to output the results to, default being shodan-search.out')
args = parser.parse_args()

SHODAN_API_KEY = "JgF8iUdjxdODTma08wfw2SySkJiGLBmK"
api = shodan.Shodan(SHODAN_API_KEY)
# defaulto search string for potential vulnerable hosts
search_string = ' port:445 "SMB Version: 1" os:Windows !product:Samba '


filename = "shodan-search.out"
if args.output:
    filename = args.output

result_limit = 500
if args.limit:
    result_limit = int(args.limit)

if args.queries: # if we have additional filters, add to the search string
    search_string += ' '.join(args.queries)

print("Searching for string: \n"+search_string)

try:
    total = 0
    results = api.search_cursor(search_string)  # an iterator for all pages of results

    with open(filename, 'w') as f:
        for i, result in enumerate(results):
            if i >= result_limit:
                break
            f.write(result['ip_str']+"\n")
        total = i

    f.close()
    print("Number of results output to %s: %d\n" % (filename, total))

except shodan.APIError as e:
    print('Error: %s' % e)
    sys.exit(1)
