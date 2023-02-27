from __future__ import annotations

import argparse
import json
import logging
import re
import time
import requests
import secrets
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from playwright._impl._api_types import Error as PlaywrightError
from playwright.sync_api import sync_playwright


class ChallengePlatform(Enum):
    """Cloudflare challenge platform URI paths."""

    JAVASCRIPT = "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/jsch/v1"
    MANAGED = "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/managed/v1"
    HCAPTCHA = "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/captcha/v1"


class Scraper:
    """
    Cookie scraper class.

    Parameters
    ----------
    user_agent : str
        User agent to use for requests.
    timeout : int
        Timeout in seconds.
    debug : bool
        Whether to run the browser in headed mode.
    proxy : Optional[str]
        Proxy to use for requests.

    Methods
    -------
    parse_clearance_cookie(cookies: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]
        Parse the cf_clearance cookie from a list of cookies.
    get_cookies(url: str) -> Optional[List[Dict[str, Any]]]
        Solve the cloudflare challenge and get cookies from the page.
    """

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: int,
        debug: bool,
        ip: str,
        proxy_server: str,
        proxy_password: str,
        api_host: str
    ) -> None:
        self._hcaptcha_solving = False
        self._message_exposed = False
        self._playwright = sync_playwright().start()
        self._ip = ip
        self._api_host = api_host

        browser = self._playwright.webkit.launch(
            headless=not debug, proxy={"server": proxy_server, "username": ip, "password": proxy_password}
        )

        context = browser.new_context(user_agent=user_agent,ignore_https_errors=True)
        context.set_default_timeout(timeout * 1000)
        self._page = context.new_page()

    def __enter__(self) -> Scraper:
        return self

    def __exit__(self, *args: Any) -> None:
        self._playwright.stop()

    def _detect_challenge(self) -> bool:
        """
        Detect if the page is a cloudflare challenge.

        Parameters
        ----------
        html : str
            HTML of the page.

        Returns
        -------
        bool
            True if the page is a cloudflare challenge, False otherwise.
        """
        return any(
            re.search(uri_path, self._page.content())
            for uri_path in (challenge.value for challenge in ChallengePlatform)
        )

    def _solve_challenge(self) -> None:
        """Solve the cloudflare challenge."""
        verify_button_pattern = re.compile(
            "Verify (I am|you are) (not a bot|(a )?human)"
        )

        verify_button = self._page.get_by_role(
            "button", name=verify_button_pattern)
        spinner = self._page.locator("#challenge-spinner")

        while self._detect_challenge():
            if spinner.is_visible():
                spinner.wait_for(state="hidden")

            challenge_stage = self._page.query_selector("div#challenge-stage")

            if verify_button.is_visible():
                verify_button.click()
                challenge_stage.wait_for_element_state("hidden")
            elif any(
                re.match(
                    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/[bg]/turnstile", frame.url)
                for frame in self._page.frames
            ):
                logging.info("Detected turnstile, reloading")
                self._page.reload()
            elif any(
                re.match("https://cf-assets.hcaptcha.com/captcha/v1", frame.url)
                for frame in self._page.frames
            ):
                self._solve_hcaptcha()

    @staticmethod
    def parse_clearance_cookie(
        cookies: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Parse the cf_clearance cookie from a list of cookies.

        Parameters
        ----------
        cookies : List[Dict[str, Any]]
            List of cookies.

        Returns
        -------
        Optional[Dict[str, Any]]
            cf_clearance cookie dictionary.
        """
        for cookie in cookies:
            if cookie["name"] == "cf_clearance":
                return cookie

        return None

    def _solve_hcaptcha(self, force=False):
        if self._hcaptcha_solving and not force:
            return

        logging.info("Solving hcaptcha...")

        js_id = self._page.evaluate(
            'document.querySelector("#cf-hcaptcha-container > div:nth-child(2) > iframe").getAttribute("data-hcaptcha-widget-id")')

        logging.info("Found hcaptcha widget id: %s" % js_id)

        time_start = time.time()
        attempt = 0

        while True:
            attempt = attempt + 1
            logging.info(f"Starting captcha solve attempt {attempt}")
            solve = requests.post(f"http://{self._api_host}/solve", timeout=60, json={
                "ip": self._ip,
                "site_key": "33f96e6a-38cd-421b-bb68-7806e1764460",
                "site_url": "https://accounts.steelseries.com/verify"
            }).json()
            if solve["success"]:
                logging.info(
                    f"Solved hcaptcha in {str(time.time() - time_start)}s")
                logging.info(solve["timings"])
                captcha = solve["token"]
                break
            else:
                logging.error(
                    f"Hcaptcha solve failed: {solve['error']}; trying again...")

        message = {
            "source": "hcaptcha",
            "label": "challenge-closed",
            "id": js_id,
            "contents": {
                "event": "challenge-passed",
                "response": captcha,
                "expiration": 120
            }
        }

        json_string = json.dumps(json.dumps(message, separators=(',', ':')))
        self._page.evaluate(f"window.postMessage({json_string})")

        self._hcaptcha_solving = True

    def get_cookies(self, url: str) -> Optional[List[Dict[str, Any]]]:
        """
        Solve the cloudflare challenge and get cookies from the page.

        Parameters
        ----------
        url : str
            URL to scrape cookies from.

        Returns
        -------
        Optional[List[Dict[str, Any]]]
            List of cookies.
        """

        try:
            self._page.goto(url)
        except PlaywrightError as err:
            logging.error(err)
            return None

        html = self._page.content()

        if re.search(ChallengePlatform.JAVASCRIPT.value, html):
            logging.info("Solving cloudflare challenge [JavaScript]...")
        elif re.search(ChallengePlatform.MANAGED.value, html):
            logging.info("Solving cloudflare challenge [Managed]...")
        elif re.search(ChallengePlatform.HCAPTCHA.value, html):
            logging.error("Cloudflare returned a captcha page.")
        else:
            logging.error("No cloudflare challenge detected.")
            return None

        try:
            self._solve_challenge()
        except PlaywrightError as e:
            logging.error(e)
            pass

        return self._page.context.cookies()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetches cf_clearance cookies from websites issuing cloudflare challenges to visitors"
    )
    parser.add_argument(
        "-v", "--verbose", help="Increase output verbosity", action="store_true"
    )
    parser.add_argument(
        "-d", "--debug", help="Run the browser in headed mode", action="store_true"
    )
    parser.add_argument(
        "-u",
        "--url",
        help="URL to fetch cf_clearance cookie from",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="File to write the cf_clearance cookie information to (JSON format)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Request timeout (seconds)",
        type=int,
        default=15,
    )
    parser.add_argument(
        "-p",
        "--proxy-host",
        help="Dorg proxy host",
        type=str,
        default=None,
        required=True
    )
    
    parser.add_argument(
        "-pa",
        "--proxy-authentication",
        help="Dorg proxy password",
        type=str,
        default=None,
        required=True
    )
    
    parser.add_argument(
        "-a",
        "--api-host",
        help="Solve/ClearanceDB host",
        type=str,
        default=None,
        required=True
    )
    
    parser.add_argument(
        "-ua",
        "--user-agent",
        help="User agent to use for requests",
        type=str,
        default="Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            format="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
            level=logging.INFO,
        )

    logging.info("Launching %s browser...",
                 "headless" if not args.debug else "headed")

    ip = f"2a10:cc46:19{secrets.token_hex(1)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}"
    logging.info("IP: %s", ip)
    with Scraper(
        user_agent=args.user_agent,
        timeout=args.timeout,
        debug=args.debug,
        ip=ip,
        proxy_server=args.proxy_host,
        proxy_password=args.proxy_authentication,
        api_host=args.api_host
    ) as scraper:
        logging.info("Going to %s...", args.url)
        timer = time.time()
        cookies = scraper.get_cookies(args.url)

        if cookies is None:
            return

        clearance_cookie = scraper.parse_clearance_cookie(cookies)
        logging.info("Everything took %f", time.time() - timer)
    if not clearance_cookie:
        logging.error("Failed to retrieve cf_clearance cookie.")
        return

    if not args.verbose:
        logging.info(clearance_cookie["value"])

    logging.info("Cookie: cf_clearance=%s", clearance_cookie["value"])
    logging.info("User agent: %s", args.user_agent)

    requests.post(f"http://{args.api_host}/clearance", json={
        "ip": ip,
        "user-agent": args.user_agent,
        "cookie": clearance_cookie["value"]
    })
    logging.info("Added cookie to database!")

    if args.file is None:
        return

    logging.info("Writing cf_clearance cookie information to %s...", args.file)

    try:
        with open(args.file, encoding="utf-8") as file:
            json_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        json_data = {"clearance_cookies": []}

    # Get the timestamp using the cookie's expiration date minus one year
    timestamp = datetime.utcfromtimestamp(
        clearance_cookie["expires"] - 31557600)

    json_data["clearance_cookies"].append(
        {
            "timestamp": timestamp.isoformat(),
            "domain": clearance_cookie["domain"],
            "cf_clearance": clearance_cookie["value"],
            "user_agent": args.user_agent,
            "proxy": args.proxy,
        }
    )

    with open(args.file, "w", encoding="utf-8") as file:
        json.dump(json_data, file, indent=4)


if __name__ == "__main__":
    main()
