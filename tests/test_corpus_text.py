from adef.core.corpus_text import record_search_text


def test_joins_title_mitre_platform_source_format_query():
    text = record_search_text({
        "title": "Suspicious mshta child",
        "mitre": ["T1218.005", "T1059.005"],
        "platform": "windows",
        "data_source": "wineventlog",
        "format": "sigma",
        "query": "process.name:mshta.exe",
    })
    assert "Suspicious mshta child" in text
    assert "T1218.005" in text
    assert "windows" in text
    assert "wineventlog" in text
    assert "process.name:mshta.exe" in text


def test_skips_empty_fields():
    text = record_search_text({"title": "Only a title"})
    assert text == "Only a title"


def test_empty_record_returns_empty_string():
    assert record_search_text({}) == ""
