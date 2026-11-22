import marshal, os, dis, sys, io, types

base = os.path.join(os.environ['TEMP'], 'uvextract', 'mods')
out = os.path.join(os.environ['TEMP'], 'uvextract', 'dump')
os.makedirs(out, exist_ok=True)


def walk(code, depth=0, path='<module>'):
    yield code, depth, path
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            yield from walk(c, depth + 1, path + '.' + c.co_name)


def summarize(code, fh):
    for c, depth, path in walk(code):
        print('  ' * depth + f'def {c.co_name}({", ".join(c.co_varnames[:c.co_argcount])})  [line {c.co_firstlineno}]', file=fh)


def consts(code, fh):
    for c, depth, path in walk(code):
        print('=' * 70, file=fh)
        print(f'{"  "*depth}FUNC {c.co_name} args={c.co_varnames[:c.co_argcount]} cells={c.co_cellvars} free={c.co_freevars}', file=fh)
        print('  VARS:', ', '.join(c.co_varnames), file=fh)
        print('  NAMES:', ', '.join(c.co_names), file=fh)
        for k in c.co_consts:
            if isinstance(k, types.CodeType):
                continue
            s = repr(k)
            if len(s) > 400:
                s = s[:400] + '...'
            print('   CONST:', s, file=fh)


for fn in sorted(os.listdir(base)):
    if not fn.endswith('.marshal'):
        continue
    name = fn[:-8]
    code = marshal.loads(open(os.path.join(base, fn), 'rb').read())
    with open(os.path.join(out, name + '.dis.txt'), 'w', encoding='utf8') as fh:
        dis.dis(code, file=fh, depth=0)
    with open(os.path.join(out, name + '.struct.txt'), 'w', encoding='utf8') as fh:
        summarize(code, fh)
        fh.write('\n\n')
        consts(code, fh)
    print('dumped', name)
