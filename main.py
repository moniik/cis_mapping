import argparse
import json
import re
import csv
import html
import sys
import os

from bs4 import BeautifulSoup
import requests
import pandas as pd

headers = {
    "Cookie": os.environ.get('COOKIE'),
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
}


def extract_control_data(html_file_path, version):

  with open(html_file_path, 'r', encoding='utf-8') as file:
    html_content = file.read()

  soup = BeautifulSoup(html_content, 'html.parser')

  table = soup.find_all('wb-recommendations-linked-to-control-modal')
  controls = []
  for row in table:
    if '(Version 8)' not in row.get('title'):
      continue
    
    for recommendation in json.loads(row.get('recommendations')):
      control = {
          'control_title': row.get('title'),
          'section_id': recommendation.get('section_id'),
          'recommendation_id': recommendation.get('id'),
          'view_level': recommendation.get('view_level'),
          'title': recommendation.get('title'),
          'pivot_control_id': recommendation.get('pivot').get('control_id'),
          'pivot_recommendation_id': recommendation.get('pivot').get('recommendation_id'),
          'url': f"https://workbench.cisecurity.org/sections/{recommendation.get('section_id')}/recommendations/{recommendation.get('pivot').get('recommendation_id')}"
      }
      controls.append(control)

  return controls


def parse_cis_controls(html_file_path):
    with open(html_file_path, 'r', encoding='utf-8') as file:
      html_content = file.read()

    soup = BeautifulSoup(html_content, 'html.parser')
    results = []

    rows = soup.find_all("tr")
    for row in rows:
        cols = row.find_all("td")
        if len(cols) < 6:
            continue

        control_id = cols[0].text.strip()
        control_title = cols[1].text.strip()

        ig_status = []
        for col in cols[2:5]:
            span = col.find("span")
            color = 'o' if span else '-'
            ig_status.append(color)


        recommendation_tag = cols[5].find("wb-recommendations-linked-to-control-modal")
        if recommendation_tag and recommendation_tag.has_attr("recommendations"):
            title_attr = recommendation_tag.get("title", "")
            if "Version 8" not in title_attr:
                continue  # Version 8 でなければスキップ

            recommendations_raw = html.unescape(recommendation_tag['recommendations'])
            try:
                recommendations = json.loads(recommendations_raw)
                for recommendation in recommendations:

                    rec_data = {
                        # 'control_title': title_attr,
                        'control_id': control_id,
                        'control': control_title,
                        'IG1': ig_status[0],
                        'IG2': ig_status[1],
                        'IG3': ig_status[2],
                        'section_id': recommendation.get('section_id'),
                        'recommendation_id': recommendation.get('id'),
                        'view_level': recommendation.get('view_level'),
                        'title': recommendation.get('title'),
                        'pivot_control_id': recommendation.get('pivot', {}).get('control_id'),
                        'pivot_recommendation_id': recommendation.get('pivot', {}).get('recommendation_id'),
                        'url': f"https://workbench.cisecurity.org/sections/{recommendation.get('section_id')}/recommendations/{recommendation.get('pivot', {}).get('recommendation_id')}"
                    }
                    results.append(rec_data)

            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")


    return results


def parse_recommendation(url: str):

  print(f'trying...{url}')
  r = requests.get(url, headers=headers)
  html_content = r.text

  soup = BeautifulSoup(html_content, 'html.parser')

  def get_wb_data(attribute):
    tag = soup.find('wb-recommendation-data', {'attribute': attribute})
    return tag.get('text', '').strip() if tag else ''

  recommendation_json = {
    "assessment_status": get_wb_data('automated_scoring'),
    "applicable_profiles": get_wb_data('profiles'),
    "description": get_wb_data('description'),
    "rationale_statement": get_wb_data('rationale_statement'),
    "impact_statement": get_wb_data('impact_statement'),
    "audit_procedure": get_wb_data('audit_procedure'),
    "remediation_procedure": get_wb_data('remediation_procedure'),
    "default_value": get_wb_data('default_value'),
  }

  return recommendation_json

 
# CIS Segment と CIS Title を抽出
def extract_cis_info(control_title: str):
    if not control_title:
        return None, None
    
    # 正規表現で "CIS Control: 16.5" 部分を分割
    match = re.search(r"CIS Control:\s*([\d.]+)\s*(.*)", control_title)
    if match:
        cis_segment = match.group(1)  # "16.5"
        cis_title = match.group(2)    # "Use Up-to-Date and Trusted Third-Party Software Components (Version 8)"
        
        # (Version 8) の部分を除去
        cis_title = re.sub(r'\s*\(Version \d+\)', '', cis_title).strip()
        
        return cis_segment, cis_title
    return None, None


def json_to_csv(input_file_path):
  df = pd.read_json(input_file_path, dtype=object)
  def normalize_profiles(profiles):
    if isinstance(profiles, list):
      return ', '.join([p['title'] for p in profiles if 'title' in p])
    return profiles if isinstance(profiles, str) else ''

  df['applicable_profiles'] = df['applicable_profiles'].apply(normalize_profiles)

  # df[['CIS_Segment', 'CIS_Title']] = df['control_title'].apply(
  #   lambda x: pd.Series(extract_cis_info(x))
  # )

  # excel
  df['control_id'] = df['control_id'].apply(lambda x: f"'{x}")
  df['view_level'] = df['view_level'].apply(lambda x: f"'{x}")

  df.to_csv(f"{input_file_path}.csv", encoding='utf-8', quoting=csv.QUOTE_ALL) 


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='parse CIS benchmark/control mapping')
  parser.add_argument('-f', '--file', type=str, help='Path to the HTML or JSON file')
  parser.add_argument('--fetch', action='store_true', help='Fetch recommendations from JSON file')
  parser.add_argument('--csv', action='store_true', help='Convert existing JSON file to CSV')
  args = parser.parse_args()

  if args.csv:
    json_to_csv(args.file)
    sys.exit(0)

  if args.fetch:
    # JSONファイルからURLを読み込んでrecommendationを取得
    with open(args.file, 'r') as f:
      mapped_data = json.load(f)
    print(f"Loaded {len(mapped_data)} records from JSON")

    all_json = []
    for i, data in enumerate(mapped_data, 1):
      print(f"[{i}/{len(mapped_data)}] {data.get('url')}")
      recommendation_json = parse_recommendation(data.get('url'))
      merged_json = {**data, **recommendation_json}
      all_json.append(merged_json)

    json_path = f'{args.file}.fetched.json'
    with open(json_path, 'w') as fw:
      fw.write(json.dumps(all_json, indent=2, ensure_ascii=False))

    json_to_csv(json_path)
    sys.exit(0)

  # HTML ファイルからCIS Controls Version 8のデータを抽出
  mapped_data = parse_cis_controls(args.file)
  print(f"Parsed {len(mapped_data)} records from HTML")

  all_json = []
  for i, data in enumerate(mapped_data, 1):
    print(f"[{i}/{len(mapped_data)}] {data.get('url')}")
    recommendation_json = parse_recommendation(data.get('url'))
    merged_json = {**data, **recommendation_json}
    all_json.append(merged_json)

  json_path = f'{args.file}.json'
  with open(json_path, 'w') as fw:
    fw.write(json.dumps(all_json, indent=2, ensure_ascii=False))

  json_to_csv(json_path)



"""
# CIS Microsoft Intune for Windows 11 Benchmark v3.0.1 -  Controls mapped to Benchmark
# https://workbench.cisecurity.org/benchmarks/16853/controls

# CIS Apple macOS 15.0 Sequoia Benchmark v1.0.0 - Controls mapped to Benchmark
# https://workbench.cisecurity.org/benchmarks/18636/controls

# CIS Google Kubernetes Engine (GKE) Benchmark v1.7.0
https://workbench.cisecurity.org/benchmarks/18949/controls

# CIS Google Kubernetes Engine (GKE) Benchmark v1.5.0
https://workbench.cisecurity.org/benchmarks/13178/controls

# CIS Google Cloud Platform Foundation Benchmark v3.0.0 - 03-29-2024
https://workbench.cisecurity.org/benchmarks/11843/controls

# CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 03-29-2024
https://workbench.cisecurity.org/benchmarks/9562/controls#

https://workbench.cisecurity.org/benchmarks/19478/controls#
"""
