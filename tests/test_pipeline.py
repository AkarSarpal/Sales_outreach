from pipeline import get_top_cve


def test_empty_list_returns_none():
    assert get_top_cve([]) is None


def test_no_kev_picks_highest_cvss():
    cves = [
        {"id": "CVE-2021-1111", "cvss_score": 5.0},
        {"id": "CVE-2021-2222", "cvss_score": 9.8},
        {"id": "CVE-2021-3333", "cvss_score": 7.2},
    ]
    assert get_top_cve(cves)["id"] == "CVE-2021-2222"


def test_kev_beats_higher_cvss():
    cves = [
        {"id": "CVE-2021-1111", "cvss_score": 9.8},
        {"id": "CVE-2021-2222", "cvss_score": 4.0},
    ]
    kev = {"CVE-2021-2222"}
    assert get_top_cve(cves, kev)["id"] == "CVE-2021-2222"


def test_highest_cvss_wins_among_kev_listed():
    cves = [
        {"id": "CVE-2021-1111", "cvss_score": 6.5},
        {"id": "CVE-2021-2222", "cvss_score": 9.1},
    ]
    kev = {"CVE-2021-1111", "CVE-2021-2222"}
    assert get_top_cve(cves, kev)["id"] == "CVE-2021-2222"


def test_scored_cve_beats_unscored_regardless_of_value():
    cves = [
        {"id": "CVE-2021-1111", "cvss_score": None},
        {"id": "CVE-2021-2222", "cvss_score": 0.1},
    ]
    assert get_top_cve(cves)["id"] == "CVE-2021-2222"


def test_unscored_wins_when_nothing_is_scored():
    cves = [
        {"id": "CVE-2021-1111", "cvss_score": None},
        {"id": "CVE-2021-2222", "cvss_score": None},
    ]
    assert get_top_cve(cves)["id"] in {"CVE-2021-1111", "CVE-2021-2222"}


def test_kev_argument_defaults_to_empty_set():
    cves = [{"id": "CVE-2021-1111", "cvss_score": 3.0}]
    assert get_top_cve(cves)["id"] == "CVE-2021-1111"
