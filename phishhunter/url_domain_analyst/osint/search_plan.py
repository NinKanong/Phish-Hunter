from __future__ import annotations
from typing import Any


def build(domain:str, company:str|None=None)->dict[str,Any]:
    d=str(domain or '').strip(); c=str(company or '').strip()
    quoted=f'"{d}"' if d else ''
    queries=[
      {'engine':'Google/Bing','query':f'site:{d} "login"' if d else '', 'purpose':'public authentication surface discovery'},
      {'engine':'Google/Bing','query':f'site:{d} ("api" OR "graphql" OR ".json")' if d else '', 'purpose':'public application endpoint references'},
      {'engine':'Google/Bing','query':f'site:{d} filetype:pdf' if d else '', 'purpose':'public documents and organizational references'},
      {'engine':'Google/Bing','query':f'{quoted} "security"' if d else '', 'purpose':'public security/vendor references'},
      {'engine':'Google/Bing','query':f'{quoted} "careers"' if d else '', 'purpose':'public workforce/company signals'},
      {'engine':'Google/Bing','query':f'"{c}" LinkedIn' if c else '', 'purpose':'manual/authorized organization research'},
    ]
    return {'queries':[q for q in queries if q['query']], 'note':'Generated query templates are for lawful, authorized research; the engine does not scrape or bypass search-engine or LinkedIn controls.'}
