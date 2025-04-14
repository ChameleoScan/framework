import json, os

import logging
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)

CACHED_IPA = []
def query_ipa(ident_or_appid: str, cache_path: str) -> tuple|None:
    '''查找缓存目录中最新版本的ipa文件，返回(appid, version, path)'''
    if not os.path.exists(cache_path):
        return None
    
    global CACHED_IPA
    ipa_files = CACHED_IPA
    if not ipa_files:
        for root, _, files in os.walk(cache_path, followlinks=True):
            for f in files:
                if not f.endswith('.ipa'):
                    continue
                try:
                    # Parse filename like "com.xuanyin.BooksList-1.1-6737224331-869938706.ipa"
                    # Split from the right since bundle id can contain - character
                    parts = os.path.splitext(f.partition(']')[2] if f.startswith('[') else f)[0].rsplit('-', 3)
                    if len(parts) != 4:
                        continue
                    bundle_id, version, appid, _ = parts
                    ipa_files.append({
                        'bundle_id': bundle_id,
                        'version': version,
                        'appid': appid,
                        'path': os.path.join(root, f)
                    })
                except:
                    logger.warning(f"Failed to parse ipa filename: {f}")
                    continue
        
        with open(os.path.join(cache_path, 'ipa_files.json'), 'w', encoding='utf-8') as f:
            json.dump(ipa_files, f, indent=4, ensure_ascii=False)

        logger.debug(f"Found {len(ipa_files)} ipa files in {cache_path}")
            
    if not ipa_files:
        return None
    
    CACHED_IPA = ipa_files
        
    # Find the ipa with matching bundle id and newest version
    matching_ipas = [ipa for ipa in ipa_files if ipa['bundle_id'] == ident_or_appid or str(ipa['appid']) == str(ident_or_appid)]
    if not matching_ipas:
        return None
        
    newest = max(matching_ipas, key=lambda x: x['version'])
    return (newest['bundle_id'], newest['appid'], newest['version'], newest['path'])



def query_appinfo(appid: str | int=None, cache_path: str|None=None, cache: dict|None=None) -> dict:
    '''查询app的基本信息, 返回name, category, description组成的字典'''
    if not cache:
        if cache_path and isinstance(cache_path, str) and os.path.exists(cache_path):
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache = json.load(f)
        else:
            from qimai_cls import get_app_baseinfo
            cache = get_app_baseinfo(str(appid))
            assert cache, "Failed to fetch app info from qimai."
    if cache_path and isinstance(cache_path, str):
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=4, ensure_ascii=False)
    return cache

def query_appcomment(appid: str = None, cache_path: str|None = None) -> list[tuple[str, str]]:
    '''查询app的评论, 返回评论列表'''
    if cache_path and isinstance(cache_path, str) and os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    from qimai_cls import get_app_comment
    comments = get_app_comment(str(appid))
    # could be empty
    #assert comments, "Failed to fetch app comments from qimai."
    
    if cache_path and isinstance(cache_path, str):
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(comments, f, indent=4, ensure_ascii=False)
            
    return comments

def query_appid_by_ident(name: str, cache_path: str|None=None, cache: int|None=None) -> int|None:
    '''根据app的ident(包名)查询appid'''
    cached_map = {}
    if cache_path and isinstance(cache_path, str):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cached_map = json.load(f)
        except:
            ...
    if name in cached_map:
        return cached_map[name]['trackId']
    else:
        if cache:
            cached_map[name] = {'trackId': cache}
        else:
            import requests
            res = requests.get(f'https://itunes.apple.com/lookup?bundleId={name}')
            res = res.json()
            if res['resultCount'] > 0:
                cached_map[name] = res['results'][0]
            else:
                return None
        if cache_path and isinstance(cache_path, str):
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cached_map, f, indent=4, ensure_ascii=False)
            
        return cached_map[name]['trackId']


if __name__ == '__main__':
    pass

