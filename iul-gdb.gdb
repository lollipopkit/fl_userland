handle SIGUSR1 noprint pass
handle SIGTTIN noprint pass
handle SIGPIPE noprint pass
set print thread-events off

# Rebuild before `run`, so that a session does not step through a binary from
# before the change under test. It was `ninja` until 2026-09-11.
define hook-run
    python
import subprocess
if subprocess.call(['tools/build-cli.sh']) != 0:
    raise gdb.CommandError('compilation failed')
    end
end

define hook-stop
    python
try:
    symtab = gdb.selected_frame().find_sal().symtab
except:
    pass
else:
    if symtab is not None and symtab.filename.endswith('.S'):
        gdb.execute('set disassemble-next-line on')
    else:
        gdb.execute('set disassemble-next-line auto')
    end
end
