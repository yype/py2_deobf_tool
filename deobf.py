"""
python2.7 pyc decompiler based on instruction simulation
"""
import argparse
import dis, marshal, sys
import StringIO
import contextlib

header_size = 8

# get output of `dis`
@contextlib.contextmanager
def stdoutIO(stdout=None):
    old = sys.stdout
    if stdout is None:
        stdout = StringIO.StringIO()
    sys.stdout = stdout
    yield stdout
    sys.stdout = old

def print2f(content, clear = False):
    with open(output_file,'a' if not clear else 'w') as f:
        f.write(content)

def get_param(code, ip):
    return ord(code[ip+1]) + 0x100 * ord(code[ip+2])

def fmsg(msg):
    return '|----------------------\n|->{}\n'.format(msg)

def rm_bracket(m):
    while '(' in m:
        m = m[:m.find('(')] + m[m.find(')')+1:]
    return m

def decompile(code, output):
    print_header = True
    args = ','.join([code.co_varnames[i] for i in range(code.co_argcount)])
    print2f('Function {}({})\n'.format(output, args))
    
    for_iters = [] # for instructions which are already explorered, skip them the second time so that we get outside of the for loop
    unexplorered = [] # branches that are not yet decompiled
    cmp_flag = False

    codes = [] # decompiled codes
    stack = [] # simulate a stack for specific instructions
    ip = 0 # current ip
    tmp_div = 0 # variable used in control flow flattening

    while True:
        comments = ''
        if ip == 280:
            pass # for debugging purposes
        with stdoutIO() as s:
            if ord(code.co_code[ip]) < 90:
                dis.dis(code.co_code[ip: ip + 1])
            else:
                dis.dis(code.co_code[ip: ip + 3])
            
        op = rm_bracket(s.getvalue().strip()[2:]).split(' ')[0]
        if 'JUMP_ABSOLUTE' in op:
            #codes.append(str(ip) + ', ' + op + '\n') # anti obfuscation
            ip = int(get_param(code.co_code, ip))
            continue
        elif 'JUMP_FORWARD' in op:
            #codes.append(str(ip) + ', ' + op + '\n')
            ip += int(get_param(code.co_code, ip)) + 3
            continue
        else:
            if 'MAKE_FUNCTION' in op:
                argc = get_param(code.co_code, ip)
                fc = stack.pop()
                argvs = []
                for i in range(argc):
                    argvs.append(stack.pop())
                stack.append('function {}\tdefault_args:{}'.format(fc, argvs))
            elif 'IMPORT_NAME' in op:
                param = get_param(code.co_code, ip)
                fromlist = stack.pop()
                level = stack.pop()
                stack.append("__import__({}, {}, {})".format(code.co_names[param], fromlist, level))
                comments = stack[-1]
            elif 'IMPORT_STAR' in op:
                comments = 'Load all symbols from {}'.format(stack.pop())
            elif 'LIST_APPEND' in op:
                param = get_param(code.co_code, ip)
                stack[-param].append(stack[-1])
                stack.pop()
            elif 'BINARY_MULTIPLY' in op:
                stack[-2] = '{}*{}'.format(stack[-2], stack[-1])
                stack.pop()
            elif 'BINARY_SUBTRACT' in op:
                stack[-2] = '{}-{}'.format(stack[-2], stack[-1])
                stack.pop()
            elif 'BINARY_SUBSCR' in op:
                stack[-2] = '{}[{}]'.format(stack[-2], stack[-1])
                stack.pop()
            elif 'STORE_NAME' in op:
                var_num = get_param(code.co_code, ip)
                arg = stack.pop()
                comments = '{} = {}'.format(code.co_names[var_num], arg)
            elif 'BINARY_ADD' in op:
                stack[-2] = '{}+{}'.format(stack[-2], stack[-1])
                stack.pop()
            elif 'LOAD_NAME' in op:
                comments = '{}'.format(code.co_names[get_param(code.co_code, ip)])
                stack.append(code.co_names[get_param(code.co_code, ip)])
            elif 'LOAD_GLOBAL' in op:
                comments = '{}'.format(code.co_names[get_param(code.co_code, ip)])
                stack.append(code.co_names[get_param(code.co_code, ip)])
            elif 'LOAD_ATTR' in op:
                stack.append(stack.pop() + '.' + code.co_names[get_param(code.co_code, ip)])
            elif 'LOAD_CONST' in op:
                const = code.co_consts[get_param(code.co_code, ip)]
                if repr(const) == "''": const = "''"
                comments = str(const)
                stack.append(const)
            elif 'GET_ITER' in op:
                stack.append('iter({})'.format(stack.pop()))
            elif 'FOR_ITER' in op:
                if ip in for_iters:
                    codes.append(fmsg('FOR %d END' % ip))
                    ip, stack = unexplorered.pop()[1:]
                    stack.pop()
                    continue
                else:
                    for_iters.append(ip)
                    unexplorered.append([ip, ip+get_param(code.co_code, ip)+3, stack[:]])
                    stack.append('{}.next()'.format(stack.pop()))
            elif 'LOAD_FAST' in op:
                comments = str(code.co_varnames[get_param(code.co_code, ip)])
                if 'DIVIDER' in op:
                    stack.append(tmp_div)
                else:
                    stack.append(code.co_varnames[get_param(code.co_code, ip)])
            elif 'STORE_FAST' in op:
                var_num = get_param(code.co_code, ip)
                arg = stack.pop()
                comments = '{} = {}'.format(code.co_varnames[var_num], arg)
                if code.co_varnames[var_num] == 'DIVIDER':
                    tmp_div = arg
                    codes = codes[:-1]
                    ip += 3
                    continue
            elif 'PRINT_ITEM' in op:
                content = stack.pop()
                comments = 'print({})'.format(content)
            elif 'PRINT_NEWLINE' in op:
                comments = 'print(\'\\n\')'
            elif 'COMPARE_OP' in op:
                a = stack.pop()
                b = stack.pop()
                if a == 'DIVIDER':
                    cmp_flag = tmp_div == b
                stack.append('{} == {}'.format(a, b))
                comments = '{} == {} ?'.format(a, b)
            elif 'CALL_FUNCTION' in op:
                if get_param(code.co_code, ip) != 0:
                    arg = stack.pop()
                else:
                    arg = ''
                func = stack.pop()
                comments = '{}({})'.format(func, arg)
                stack.append('{}({})'.format(func, arg))
            elif 'RETURN_VALUE' in op:
                comments = 'return {}'.format(stack.pop())
            elif 'POP_TOP' in op:
                stack.pop()
            elif 'POP_JUMP_IF_FALSE' in op:
                unexplorered.append([ip, get_param(code.co_code, ip), stack[:]])
                stack.pop()
            elif 'BUILD_LIST' in op:
                size_of_list = get_param(code.co_code, ip)
                tmp = []
                for i in range(size_of_list):
                    tmp = [stack.pop()] + tmp
                stack.append(tmp)
            elif 'SETUP_LOOP' in op or 'POP_BLOCK' in op:
                pass
            elif 'RAISE_VARARGS' in op:
                argc = get_param(code.co_code, ip)
                argvs = []
                argvns = ['Exception:','Parameter:','Traceback:']
                for i in range(argc):
                    argvs.append(argvns[i] + str(stack.pop()))
                comments = 'raise Exception(' + ', '.join(argvs) + ')'
            elif 'POP_JUMP_IF_TRUE' in op:
                stack.pop()
                if 'DIVIDER' in codes[-2]: # anti o-llvm
                    if cmp_flag:
                        ip = get_param(code.co_code, ip)
                    else: 
                        ip += 3
                    codes = codes[:-3] 
                    continue
                else:
                    unexplorered.append([ip, get_param(code.co_code, ip), stack[:]])
                    stack.pop()

            else:
                raise Exception('Opcode `{}` not handled'.format(op))
            
            form = "{:<5}\t{:<20}\t{:<6}\t{:<30}\n"
            if print_header:
                codes.append(form.format('IP', 'INSN', 'PARAM', 'COMMENTS'))
                print_header = False
            insn = form.format(
                str(ip), op, 
                get_param(code.co_code, ip) if ord(code.co_code[ip]) >= 90 else '',
                comments
            )
            codes.append(insn)
    
            if ord(code.co_code[ip]) < 90:
                ip += 1
            else:
                ip += 3
        
        if 'RETURN_VALUE' in op:
            if len(unexplorered) == 0:
                print2f(''.join(codes))
                args = ','.join([code.co_varnames[i] for i in range(code.co_argcount)])
                print2f('Function {}({}) End\n\n\n'.format(output, args))
                break
            else:
                from_ip, new_ip, stack = unexplorered.pop()
                codes.append(fmsg('referenced by %d' % from_ip))
                ip = new_ip



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Python2.7 pyc deobfuscator')
    parser.add_argument('pyc', metavar='filename', type=str, nargs=1, 
        help='file to deobfuscate'
    )
    input_file = parser.parse_args().pyc[0]
    output_file = input_file + '.deobf.txt'

    with open(input_file, "rb") as f:
        magic_and_timestamp = f.read(header_size)  # first 8 or 12 bytes are metadata
        code = marshal.load(f)                     # rest is a marshalled code object

    # get sub functions
    func_list = []
    for x in code.co_consts:
        if type(x) == type(code):
            func_list.append(x)

    print2f("Decompilation results for {}\n\n".format(input_file), clear = True)

    # decompile the `<module>()` function
    decompile(code, '%s' % code.co_name)

    for x in func_list:
        # decompile sub functions
        """
        print dir(x),x.co_name
        print x.co_names
        print x.co_consts
        print x.co_varnames
        print
        """
        decompile(x, '%s' % x.co_name)
    
    print 'Decompilation results saved to {}'.format(output_file)

