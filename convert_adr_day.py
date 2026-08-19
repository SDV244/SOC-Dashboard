#!/usr/bin/env python3
"""Convert ONE day of ADR to parquet. Called by ingest_adr_v3.sh.
Usage: python3 convert_adr_day.py <year> <month> <day>
Exit 0 = success or already done. Exit 1 = failed."""
import sys
import os
from pathlib import Path

year, month, day = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
dst = Path(f"/data/parquet/index=adr/year={year}/month={month:02d}/day={day:02d}.parquet")
dst_tmp = dst.parent / f".tmp_{dst.name}"
dst.parent.mkdir(parents=True, exist_ok=True)

import duckdb

def is_valid(path):
    try:
        c = duckdb.connect(":memory:")
        n = c.execute("SELECT count(*) FROM parquet_scan('" + str(path) + "')").fetchone()[0]
        c.close()
        return n > 0
    except Exception:
        return False

# Skip if already valid
if dst.exists() and dst.stat().st_size > 0 and is_valid(dst):
    print(f"SKIP {dst.name}: already valid", flush=True)
    sys.exit(0)

# Remove corrupt/incomplete destination and any leftover temp
if dst.exists():
    dst.unlink()
if dst_tmp.exists():
    dst_tmp.unlink()

sys.path.insert(0, "/app")
from backend.config import get_settings
from backend.db import setup_httpfs

s = get_settings()
src = (
    f"s3://{s.s3_bucket}/"
    f"organization={s.org_id}/index=adr/tenant={s.tenant_id}/"
    f"year={year:04d}/month={month:02d}/day={day:02d}/**/*.gz"
)

SELECT_COLS = """
    to_timestamp(CAST(timestamp AS BIGINT) / 1000)::TIMESTAMPTZ AS ts,
    COALESCE(threat_score, TRY_CAST(risk_score AS INTEGER))       AS threat_score,
    severity, confidence,
    is_dga AS dga_flag, is_tunneling AS tunneling,
    srcip AS src_ip, srcip_type,
    srcip_geo.countryCode AS country_code,
    dstip AS dst_ip, srcport AS src_port, dstport AS dst_port, proto,
    engid_name, appid_name,
    CASE WHEN domain_list IS NOT NULL AND len(domain_list) > 0
         THEN domain_list[1] ELSE NULL END AS primary_domain,
    domain_list AS all_domains, domain_reputation,
    kill_chain_stage, tactic, technique, msg_class,
    COALESCE(NULLIF(event_type,''),NULLIF(task,''),NULLIF(event.type,''),
        CASE WHEN data_sources IS NOT NULL AND len(data_sources)>0
             THEN data_sources[1] END) AS event_type,
    host,
    COALESCE(NULLIF(user_name,''),NULLIF(username,''),NULLIF(login_user,''),
        NULLIF(exec_user,''),NULLIF(event_data['SubjectUserName'],''),
        NULLIF(event_data['TargetUserName'],''),NULLIF(srcip_username,''),
        NULLIF(hostip_username,''),NULLIF(process_user,''),NULLIF(user.name,''),
        CASE WHEN name IS NOT NULL AND len(name)>0 THEN name[1] END) AS user_name,
    COALESCE(NULLIF(hostname,''),NULLIF(computer_name,''),NULLIF(hostip_host,'')) AS hostname,
    login_type, login_result, fidelity, actual, typical,
    COALESCE(NULLIF(process_name,''),NULLIF(process.name,''),NULLIF(file_path,'')) AS process_name,
    COALESCE(NULLIF(parent_proc_name,''),NULLIF(process.parent.name,'')) AS parent_proc_name,
    hostip AS host_ip, event_id, srcip_reputation, dstip_reputation,
    weighted_anomaly_score, result
"""

READ_COLS = """{
    'timestamp':'BIGINT','threat_score':'INTEGER','severity':'VARCHAR',
    'confidence':'INTEGER','is_dga':'VARCHAR','is_tunneling':'INTEGER',
    'srcip':'VARCHAR','srcip_type':'VARCHAR',
    'srcip_geo':'STRUCT(countryCode VARCHAR)',
    'dstip':'VARCHAR','srcport':'INTEGER','dstport':'INTEGER','proto':'VARCHAR',
    'engid_name':'VARCHAR','appid_name':'VARCHAR','domain_list':'VARCHAR[]',
    'domain_reputation':'VARCHAR','kill_chain_stage':'VARCHAR','tactic':'VARCHAR',
    'technique':'VARCHAR','msg_class':'VARCHAR','event_type':'VARCHAR',
    'host':'VARCHAR','user_name':'VARCHAR','username':'VARCHAR',
    'login_user':'VARCHAR','exec_user':'VARCHAR',
    'event_data':'MAP(VARCHAR, VARCHAR)','srcip_username':'VARCHAR',
    'srcip_usersid':'VARCHAR','hostip_username':'VARCHAR','hostip_usersid':'VARCHAR',
    'process_user':'VARCHAR','hostname':'VARCHAR','computer_name':'VARCHAR',
    'login_type':'VARCHAR','login_result':'VARCHAR','fidelity':'INTEGER',
    'actual':'DOUBLE','typical':'DOUBLE','process_name':'VARCHAR',
    'parent_proc_name':'VARCHAR','hostip':'VARCHAR','event_id':'INTEGER',
    'srcip_reputation':'VARCHAR','dstip_reputation':'VARCHAR',
    'weighted_anomaly_score':'DOUBLE','result':'VARCHAR','name':'VARCHAR[]',
    'risk_score':'DOUBLE','data_sources':'VARCHAR[]',
    'user':'STRUCT(name VARCHAR)',
    'process':'STRUCT(name VARCHAR, parent STRUCT(name VARCHAR))',
    'event':'STRUCT(type VARCHAR)','hostip_host':'VARCHAR',
    'file_path':'VARCHAR','task':'VARCHAR'
}"""

conn = duckdb.connect(":memory:")
setup_httpfs(conn)
conn.execute("SET memory_limit='2500MB'")
conn.execute("SET temp_directory='/data/duckdb_tmp'")

try:
    conn.execute(
        f"COPY (SELECT {SELECT_COLS} FROM read_json('{src}',"
        f" format='newline_delimited', compression='gzip',"
        f" ignore_errors=true, columns={READ_COLS}))"
        f" TO '{dst_tmp}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)"
    )
    conn.close()
    os.sync()
    val = duckdb.connect(":memory:")
    n = val.execute("SELECT count(*) FROM parquet_scan('" + str(dst_tmp) + "')").fetchone()[0]
    val.close()
    if n == 0:
        raise Exception("0 rows written")
    os.rename(str(dst_tmp), str(dst))
    print(f"OK {dst.name}: {n:,} rows", flush=True)
    sys.exit(0)
except Exception as e:
    print(f"FAIL {dst.name}: {e}", flush=True)
    try:
        dst_tmp.unlink()
    except OSError:
        pass
    sys.exit(1)
