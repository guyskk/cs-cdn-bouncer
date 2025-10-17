from app.config import CONFIG
from app.tencent_edgeone_api import TencentEdgeoneAPI


def test_tencent_edgeone_api_basic():
    teo_api = TencentEdgeoneAPI(
        secret_id=CONFIG.tencent_secret_id,
        secret_key=CONFIG.tencent_secret_key,
    )
    ret = teo_api.list_zone()
    assert ret, "zone not found"
    config = teo_api.get_zone_config(zone_id=CONFIG.tencent_teo_zone_id)
    assert config, "zone config not found"
