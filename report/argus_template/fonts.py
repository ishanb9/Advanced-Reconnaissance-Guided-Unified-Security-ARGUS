"""Fetch Google Fonts woff2 files, keep latin + latin-ext subsets, base64-embed
them as @font-face data-URI rules. Output: build/assets_fonts.css (self-contained)."""
import urllib.request, re, base64, os, sys

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'assets_fonts.css')

# Keep only these subsets (by the comment label Google emits before each @font-face)
KEEP_SUBSETS = {'latin', 'latin-ext'}

FAMILIES = [
    # (css2 query, human name)
    ('Fraunces:ital,opsz,wght@0,9..144,340..640;1,9..144,340..600', 'Fraunces'),
    ('IBM+Plex+Sans:wght@400;500;600;700', 'IBM Plex Sans'),
    ('IBM+Plex+Mono:wght@400;500;600', 'IBM Plex Mono'),
]

def fetch(url):
    return urllib.request.urlopen(
        urllib.request.Request(url, headers={'User-Agent': UA}), timeout=40).read()

def process_family(query):
    css = fetch('https://fonts.googleapis.com/css2?family=%s&display=swap' % query).decode()
    # Google emits: /* subset */\n@font-face { ... }  blocks
    blocks = re.split(r'(?=/\*\s*[a-z0-9-]+\s*\*/)', css)
    out = []
    total = 0
    for b in blocks:
        m = re.match(r'/\*\s*([a-z0-9-]+)\s*\*/', b.strip())
        if not m:
            continue
        subset = m.group(1)
        if subset not in KEEP_SUBSETS:
            continue
        url_m = re.search(r'url\((https://[^)]+\.woff2)\)', b)
        if not url_m:
            continue
        data = fetch(url_m.group(1))
        total += len(data)
        b64 = base64.b64encode(data).decode()
        datauri = 'url(data:font/woff2;base64,%s) format("woff2")' % b64
        block = re.sub(r'url\(https://[^)]+\.woff2\)\s*format\([^)]*\)', datauri, b)
        # also handle case where format() absent
        block = re.sub(r'url\(https://[^)]+\.woff2\)', datauri, block)
        out.append(block.strip())
    return out, total

def main():
    all_blocks = []
    grand = 0
    for query, name in FAMILIES:
        blocks, total = process_family(query)
        grand += total
        print('%-16s %2d faces  %6.1f KB raw woff2' % (name, len(blocks), total/1024))
        all_blocks.extend(blocks)
    css = '\n'.join(all_blocks) + '\n'
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(css)
    print('-' * 44)
    print('TOTAL raw woff2 %.1f KB -> %s (%.1f KB base64 css)' %
          (grand/1024, os.path.basename(OUT), os.path.getsize(OUT)/1024))

if __name__ == '__main__':
    main()
