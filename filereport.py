import asyncio
import aiohttp
from filehash import get_file_hash
from filepath import get_files_path


async def get_file_report(path: str, apikey: str, session: aiohttp.ClientSession, *, manual: bool = False,
                          show_undetected: bool) -> str:
    """Queries VT serves and returns a parsed report"""
    digest = get_file_hash(path, manual=manual)
    params = {'apikey': apikey, 'resource': digest}
    async with session.get('https://www.virustotal.com/vtapi/v2/file/report', params=params) as response:
        return await parse_report(path, response, show_undetected=show_undetected)


async def parse_report(path: str, report: aiohttp.ClientResponse, *, show_undetected: bool) -> str:
    """Parses a report and returns a string output accordingly"""
    if report.status == 200:
        content = await report.json()
        if content['response_code'] == -2 or content['response_code'] == 0:
            return f'{path}...  <span style="color: #ffd82e;">Info Not Found!</span>'
        else:
            if content['positives'] > 0:
                return f'{path}... <span style="color: red;">Detected! ({content["positives"]}/{content["total"]})</span>'
            elif show_undetected and content['positives'] == 0:
                return f'{path}... <span style="color: #42c965;">Undetected!</span>'
    elif report.status == 204:
        return f'{path}... <span style="color: #ffd82e;">Failed! (Request Limit Exceeded)</span>'
    elif report.status == 400:
        return f'{path}... <span style="color: #ffd82e;">Failed! (Invalid Arguments)</span>'
    elif report.status == 403:
        return f'{path}... <span style="color: #ffd82e;">Failed! (Forbidden)</span>'


async def scan(path: str, apikey: str, show_undetected: bool, manual: bool = False) -> str:
    """Scans a given dir path topdown and yields parsed reports"""
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            *[get_file_report(file, apikey, session, manual=manual, show_undetected=show_undetected)
                for file in get_files_path(path)],
            return_exceptions=True)

    for result in results:
        yield result
