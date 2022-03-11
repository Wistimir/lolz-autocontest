import re
from typing import Union
import time

import settings

pattern_captcha_sid = re.compile(r"sid\s*:\s*'([0-9a-f]{32})'", re.MULTILINE)
pattern_captcha_dot = re.compile(r'XenForo.ClickCaptcha.dotSize\s*=\s*(\d+);', re.MULTILINE)
pattern_captcha_img = re.compile(r'XenForo.ClickCaptcha.imgData\s*=\s*"([A-Za-z0-9+/=]+)";', re.MULTILINE)
pattern_hint_letter = re.compile(r'Starts with \'(.)\' letter', re.MULTILINE)


class SolverAnswers:
    def __init__(self, puser):
        self.puser = puser

    def solve(self, captcha_block_soup, **kwargs) -> Union[dict, None]:
        time.sleep(settings.solve_time)
        question = captcha_block_soup.find("div", attrs={"class": "ddText"}).text
        placeholder = captcha_block_soup.find("input", attrs={"id": "CaptchaQuestionAnswer"})["placeholder"]

        # TODO: add exact thread_id search
        params = {
            "id": kwargs["id"],
            "q": question,
        }

        if placeholder:
            params["l"] = pattern_hint_letter.search(placeholder).group(1)

        response = self.puser.make_request("GET", "https://" + settings.answers_server + "/query.php", params=params,
                                           timeout=12.05, retries=3, check_for_js=False)

        if response is None:
            return None

        resp = response.json()

        if resp["status"] < 0:
            self.puser.logger.warning("%d doesn't have an answer. blacklisting for 5 minutes", kwargs["id"])
            settings.ExpireBlacklist[kwargs["id"]] = time.time() + 300 # TODO: make configurable timeout
            return None
        if resp["status"] > 0: # TODO: make this check configurable
            self.puser.logger.warning("%d %d answer isn't exact. blacklisting for 5 minutes", resp["threadid"], resp["id"])
            settings.ExpireBlacklist[kwargs["id"]] = time.time() + 300
            return None
        self.puser.logger.verbose("using %d %d %d", resp["threadid"], resp["id"], resp["status"])

        return {
            'captcha_question_answer': resp["answer"],
            'captcha_type': "AnswerCaptcha",
        }