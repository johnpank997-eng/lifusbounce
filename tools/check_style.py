from pathlib import Path
import ast
import io
import re
import sys
import tokenize

Root = Path(__file__).resolve().parents[1]


def CodeTokens(text):
    output = list(text)
    comments = []
    index = 0
    while index < len(text):
        end = index + 1
        comment = False
        if text.startswith('//', index):
            end = text.find('\n', index)
            if end < 0:
                end = len(text)
            comment = True
        elif text.startswith('/*', index):
            end = text.index('*/', index + 2) + 2
            comment = True
        elif text.startswith('R"', index):
            opening = text.index('(', index + 2)
            delimiter = text[index + 2:opening]
            end = text.index(')' + delimiter + '"', opening) + len(delimiter) + 2
        elif text[index] in ('"', "'"):
            quote = text[index]
            end = index + 1
            while end < len(text):
                if text[end] == '\\':
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
        else:
            index += 1
            continue
        if comment:
            comments.append(text.count('\n', 0, index) + 1)
        for at in range(index, min(end, len(text))):
            if output[at] != '\n':
                output[at] = ' '
        index = end
    return ''.join(output), comments


def Main():
    errors = []
    checked = 0
    for folder in ('src', 'resources', 'driver', 'tools'):
        for path in (Root / folder).rglob('*'):
            if path.suffix not in ('.cpp', '.hpp', '.c', '.h', '.rc', '.py', '.cmd'):
                continue
            checked += 1
            text = path.read_text(encoding='utf-8')
            name = path.relative_to(Root).as_posix()
            if path.suffix in ('.cpp', '.hpp', '.c', '.h', '.rc'):
                code, lines = CodeTokens(text)
                errors.extend(f'{name}:{line}: comment' for line in lines)
                if path.suffix in ('.cpp', '.hpp'):
                    for match in re.finditer(r'^\s*(?:class|struct|enum(?:\s+(?:class|struct))?|using)\s+(\w+)', code, re.M):
                        symbol = match.group(1)
                        if symbol == 'namespace':
                            continue
                        if not re.fullmatch(r'[A-Z][A-Za-z0-9]*', symbol):
                            errors.append(f'{name}: type naming: {symbol}')
            elif path.suffix == '.py':
                for token in tokenize.generate_tokens(io.StringIO(text).readline):
                    if token.type == tokenize.COMMENT:
                        errors.append(f'{name}:{token.start[0]}: comment')
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                        if ast.get_docstring(node):
                            errors.append(f'{name}: embedded documentation')
            elif re.search(r'^\s*(?:rem\s|::)', text, re.M | re.I):
                errors.append(f'{name}: comment')
    for filename in ('.gitignore', '.gitattributes'):
        if any(line.lstrip().startswith('#') for line in (Root / filename).read_text().splitlines()):
            errors.append(f'{filename}: comment')
    if errors:
        print('\n'.join(errors))
        return 1
    print(f'pass: {checked} project files; no comments or embedded docs; PascalCase types')
    return 0


if __name__ == '__main__':
    sys.exit(Main())
