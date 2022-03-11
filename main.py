from traceback_with_variables import Format, ColorSchemes, global_print_exc, printing_exc, LoggerAsFile
from bs4 import BeautifulSoup
from typing import Union
import re
import json
import time
import coloredlogs
import verboselogs
from logging.handlers import RotatingFileHandler
import sys
from Crypto.Cipher import AES
import httpx

import settings
import solvers

fmterr = Format(
    max_value_str_len=-1,
    color_scheme=ColorSchemes.common,
    max_exc_str_len=-1,
)
global_print_exc(fmt=fmterr)

level_styles = {'debug': {'color': 8},
                'info': {},
                'warning': {'color': 11},
                'error': {'color': 'red'},
                'critical': {'bold': True, 'color': 'red'},

                'spam': {'color': 'green', 'faint': True},
                'verbose': {'color': 'blue'},
                'notice': {'color': 'magenta'},
                'success': {'bold': True, 'color': 'green'},
                }

logfmtstr = "%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s"
logfmt = coloredlogs.ColoredFormatter(logfmtstr, level_styles=level_styles)

# rotate every 4 megs
fileHandler = RotatingFileHandler(
    "lolzautocontest.log", maxBytes=1024 * 1024 * 4, backupCount=10, encoding='utf-8')
fileHandler.setFormatter(logfmt)

pattern_csrf = re.compile(r'_csrfToken:\s*\"(.*)\",', re.MULTILINE)
pattern_df_id = re.compile(
    r'document\.cookie\s*=\s*"([^="]+)="\s*\+\s*toHex\(slowAES\.decrypt\(toNumbers\(\"([0-9a-f]{32})\"\)', re.MULTILINE)


# consoleHandler = logging.StreamHandler(sys.stdout)
# consoleHandler.setFormatter(logfmt)


class User:
    def make_request(self,
                     method: str,
                     url,
                     check_for_js=False,
                     retries=1,
                     **kwargs) -> Union[httpx.Response, None]:
        for i in range(0, retries):
            try:
                resp = self.session.request(method, url, **kwargs)
                resp.raise_for_status()
            except httpx.TimeoutException as e:
                self.logger.warning("%s timeout", e.request.url)
                time.sleep(settings.low_time)
            except httpx.ProxyError as e:
                self.logger.warning("%s proxy error (%s)",
                                    e.request.url, str(e))
                time.sleep(settings.low_time)
            except httpx.TransportError as e:
                self.logger.warning("%s TransportError (%s)",
                                    e.request.url, str(e))
                time.sleep(settings.low_time)
            except httpx.HTTPStatusError as e:
                self.logger.warning(
                    "%s responded with %s status", e.request.url, e.response.status_code)
                time.sleep(settings.low_time)
            else:
                if check_for_js:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    if self.check_for_js_and_fix(soup):
                        self.logger.debug("%s had JS PoW", url)
                        continue  # we have js gayness

                return resp
        else:
            return None  # failed after x retries

    def check_for_js_and_fix(self, soup):
        no_script = soup.find("noscript")
        if not no_script:
            return False
        p_string = no_script.find("p")
        if not (p_string and p_string.string == "Oops! Please enable JavaScript and Cookies in your browser."):
            return False
        script = soup.find_all("script")
        if not script:
            return False
        if not (script[1].string.startswith(
                'var _0xe1a2=["\\x70\\x75\\x73\\x68","\\x72\\x65\\x70\\x6C\\x61\\x63\\x65","\\x6C\\x65\\x6E\\x67\\x74\\x68","\\x63\\x6F\\x6E\\x73\\x74\\x72\\x75\\x63\\x74\\x6F\\x72","","\\x30","\\x74\\x6F\\x4C\\x6F\\x77\\x65\\x72\\x43\\x61\\x73\\x65"];function ')
                and script[0].get("src") == '/aes.js'):
            return False

        self.logger.verbose("lolz asks to complete aes task")

        match = pattern_df_id.search(script[1].string)
        cipher = AES.new(bytearray.fromhex("e9df592a0909bfa5fcff1ce7958e598b"), AES.MODE_CBC,
                         bytearray.fromhex("5d10aa76f4aed1bdf3dbb302e8863d52"))
        value = cipher.decrypt(bytearray.fromhex(match.group(2))).hex()
        self.logger.debug("PoW answer %s", str(value))
        self.session.cookies.set(domain="." + settings.lolz_domain,
                                 name=match.group(1),
                                 value=value)
        return True  # should retry

    def solve_page(self) -> bool:  # return whether we found any contests or not
        found_contest = False
        contest_list_resp = self.make_request("GET",
                                              settings.lolz_url + "forums/contests/",
                                              timeout=12.05,
                                              retries=3,
                                              check_for_js=True)
        if contest_list_resp is None:
            return False

        contest_list_soup = BeautifulSoup(contest_list_resp.text, "html.parser")

        contest_list = contest_list_soup.find("div", class_="discussionListItems")
        if contest_list is None:
            self.logger.critical("%s", str(contest_list_soup))
            raise RuntimeError("couldn't find discussionListItems.")

        threads_list = []

        sticky_threads = contest_list.find("div", class_="stickyThreads")
        if sticky_threads:
            threads_list.extend(sticky_threads.findChildren(recursive=False))

        latest_threads = contest_list.find("div", class_="latestThreads")
        if latest_threads:
            threads_list.extend(latest_threads.findChildren(recursive=False))

        if len(threads_list) == 0:
            return False
        # TODO: make threads_list a list of thread_ids instead of html objects
        # also remove all blacklisted thread_ids before we get to this point
        self.logger.notice("detected %d contests", len(threads_list))
        for contestDiv in threads_list:
            thr_id = int(contestDiv.get('id').split('-')[1])

            if thr_id in self.blacklist or thr_id in settings.ExpireBlacklist:
                continue
            found_contest = True
            contest_name = contestDiv.find("div", class_="discussionListItem--Wrapper") \
                .find("a", class_="listBlock main PreviewTooltip") \
                .find("h3", class_="title").find("span", class_="spanTitle").contents[0]
            # this is not very nice but should avoid the bug with not sleeping when skipping for some reason
            time.sleep(settings.switch_time)

            self.logger.notice(
                "participating in %s thread id %d", contest_name, thr_id)

            # TODO: stuff bellow probably should get it's own function

            contest_resp = self.make_request("GET",
                                             settings.lolz_url + "threads/" +
                                             str(thr_id) + "/",
                                             retries=3,
                                             timeout=12.05,
                                             check_for_js=True)
            if contest_resp is None:
                continue

            contest_soup = BeautifulSoup(contest_resp.text, "html.parser")

            script = contest_soup.find("script", text=pattern_csrf)
            if script is None:
                self.logger.error("%s", str(contest_soup))
                raise RuntimeError("no csrf token!")

            csrf = pattern_csrf.search(script.string).group(1)
            if not csrf:
                self.logger.critical("%s", str(contest_soup))
                raise RuntimeError("csrf token is empty. likely bad cookies")
            self.logger.debug("csrf: %s", str(csrf))

            div_captcha = contest_soup.find("div", class_="captchaBlock")
            if div_captcha is None:
                self.logger.warning(
                    "Couldn't get captchaBlock. Lag or contest is over?")
                continue

            captcha_type_obj = div_captcha.find(
                "input", attrs={"name": "captcha_type"})

            if captcha_type_obj is None:
                self.logger.warning(
                    "captcha_type not found. adding to blacklist...")
                self.blacklist.add(thr_id)
                continue

            captcha_type = captcha_type_obj.get("value")

            solver = self.solvers.get(captcha_type)
            if solver is None:
                raise RuntimeError(f"\"{captcha_type}\" doesn't have a solver.")

            self.logger.verbose("for %s using solver %s",
                                captcha_type, type(solver).__name__)

            participate_params = solver.solve(div_captcha, id=thr_id)
            if participate_params is None:
                continue

            self.logger.debug("waiting for participation...")
            response = self.participate(str(thr_id), csrf, participate_params)
            if response is None:
                continue

            if "error" in response and response["error"][0] == 'Вы не можете участвовать в своём розыгрыше.':
                self.blacklist.add(thr_id)

            if "_redirectStatus" in response and response["_redirectStatus"] == 'ok':
                self.logger.success(
                    "successfully participated in %s thread id %s", contest_name, thr_id)
            else:
                if captcha_type == "AnswerCaptcha":  # TODO: this is kina a hack
                    self.logger.error("%s has wrong answer", thr_id)
                    settings.ExpireBlacklist[thr_id] = time.time() + 300000
                self.logger.error("didn't participate: %s", str(response))
            self.logger.debug("%s", str(response))
        return found_contest

    def work(self):
        with printing_exc(file_=LoggerAsFile(self.logger), fmt=fmterr):
            start_time = time.time()
            found_contest = 0

            self.logger.debug("work cookies %s", str(self.session.cookies))
            self.logger.debug("work headers %s", str(self.session.headers))
            ip = self.make_request(
                "GET", "https://httpbin.org/ip", timeout=12.05, retries=30)
            if ip:
                self.logger.notice("ip: %s", ip.json()["origin"])
            else:
                raise RuntimeError(
                    "Wasn't able to reach httpbin.org in 30 tries. Check your proxies and your internet connection")
            while True:
                cur_time = time.time()
                # remove old entries
                settings.ExpireBlacklist = {
                    k: v for k, v in settings.ExpireBlacklist.items() if v > cur_time}
                self.logger.info("loop at %.2f seconds (blacklist size %d)", cur_time - start_time,
                                 len(settings.ExpireBlacklist))

                if self.solve_page():
                    found_contest = settings.found_count

                if found_contest > 0:
                    found_contest -= 1
                    time.sleep(settings.low_time)
                else:
                    time.sleep(settings.high_time)

    def __init__(self, parameters):
        self.session = httpx.Client(http2=True)
        self.username = parameters[0]

        self.logger = verboselogs.VerboseLogger(self.username)
        self.logger.addHandler(fileHandler)
        # self.logger.addHandler(consoleHandler)
        coloredlogs.install(fmt=logfmtstr, stream=sys.stdout, level_styles=level_styles,
                            milliseconds=True, level='DEBUG', logger=self.logger)
        self.logger.debug("user parameters %s", parameters)

        self.session.headers.update(
            {"User-Agent": parameters[1]["User-Agent"]})
        for key, value in parameters[1]["cookies"].items():
            self.session.cookies.set(
                domain="." + settings.lolz_domain,
                name=key,
                value=value)

        self.blacklist = set()

        self.solvers = {
            "AnswerCaptcha": solvers.SolverAnswers(self),
        }

        self.session.cookies.set(
            domain=settings.lolz_domain, name='xf_viewedContestsHidden', value='1')
        self.session.cookies.set(
            domain=settings.lolz_domain, name='xf_feed_custom_order', value='post_date')
        self.session.cookies.set(
            domain=settings.lolz_domain, name='xf_logged_in', value='1')

    def participate(self, thread_id: str, csrf: str, data: dict):
        # https://stackoverflow.com/questions/6005066/adding-dictionaries-together-python
        response = self.make_request("POST", settings.lolz_url + "threads/" + thread_id + "/participate",
                                     data={**data, **{
                                         '_xfRequestUri': "/threads/" + thread_id + "/",
                                         '_xfNoRedirect': 1,
                                         '_xfToken': csrf,
                                         '_xfResponseType': "json",
                                     }}, timeout=12.05, retries=3, check_for_js=True)

        if response is None:
            return None

        try:
            parsed = json.loads(response.text)
            self.logger.debug("parsed")
        except ValueError:
            self.logger.critical("SOMETHING BAD 2!!\n%s", response.text)
            raise

        return parsed


def main():
    User(['user', settings.user]).work()


if __name__ == '__main__':
    main()
