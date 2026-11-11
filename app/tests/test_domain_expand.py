from pin_manager.domain_expand import expand_sinkhole_domains, partition_apex_for_sinkhole


def test_expand_from_url_in_blacklist():
    names = expand_sinkhole_domains(["https://www.youtube.com"])
    assert "youtube.com" in names
    assert all("://" not in n for n in names)


def test_expand_youtube():
    names = expand_sinkhole_domains(["youtube.com"])
    assert "youtube.com" in names
    assert "www.youtube.com" in names
    assert "googlevideo.com" in names


def test_partition_hsts_silent():
    portal, silent = partition_apex_for_sinkhole(
        ["youtube.com", "centrum.cz"], https_silent=True
    )
    assert "youtube.com" in silent
    assert "centrum.cz" in portal
    assert "youtube.com" not in portal


def test_partition_portal_pin_on_hsts_when_not_silent():
    portal, silent = partition_apex_for_sinkhole(
        ["youtube.com", "centrum.cz"], https_silent=False
    )
    assert "youtube.com" in portal
    assert "centrum.cz" in portal
    assert silent == []
