from pin_manager.domain_expand import expand_sinkhole_domains


def test_expand_youtube():
    names = expand_sinkhole_domains(["youtube.com"])
    assert "youtube.com" in names
    assert "www.youtube.com" in names
    assert "googlevideo.com" in names
