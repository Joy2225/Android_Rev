
# Initialize

```python
import angr
import calrify
proj = angr.Project('crack') # The filemane
```

# Decide where to start the state from

```python
state = proj.factory.full_init_state() # Starts from _start
state = proj.factory.entry_state() # Starts from _entry
```

# Make Simulation manager and pass the state to it

```python
simgr = proj.factory.simgr(state)
simgr = proj.factory.simulation_manager()
```

# Find a path to a certain address

```python
simgr.explore(find=0x80485e0, avoid=0x80485a8)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1))
```

# See and dump found states

```python
s = sigmr.found[0] # First found state if any
# Dump the input/output
print(s.posix.dumps(0)) # 0 : stdin, 1 : stdout 
```

# If needed to start from a specific address

```python
state = proj.factory.entry_state(addr = 0xxxxxxxx) # Starts from the address stated
arg = clarify.BVS('arg', 8*50) # create the symbolic vector. Needed to store the key prolly. Depends
state.memory.store(state.regs.rbp-0x99, arg) # Need to set the state. 0x99 is problem specific
simgr = proj.factory.simgr(state)
simgr.explore(find = <address_needed>)
simgr.found[0].solver.eval(arg, cast_to=bytes)
```

# General

```python
state.step() # It will come to the part before any branching ig. But the state var will still be the same

# We can make sigmr and then do sigmr.step() and then see the value in the memory of any address
simgr.step()
s = simgr.active[0]
s.mem['0x<addr>'].string.concrete # Only string will give raw bytes

# Step until everything terminates
simgr.run()
```

# Veritesting

Need to understand it better.

```python
simgr = proj.factory.simulation_manager(veritesting=True)
```

# Find Symbols

```python
symbol_name = proj.loader.find_symbol("read_and_print_flag").rebased_addr
```

# Print stuff in a loop

```python
for s in simgr.deadended:
	print(s.posix.stdput.concretize())
```

# Hook function for scripting + Debugging

```python
def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', confirm_exit=False)
    exit(0)

...Relevant code

hook(locals())
```

# Put assertions

```python
from string import printable
user_data = claripy.BVS("user_data", 36*8)
state = proj.factory.entry_state(stdin=user_data)
for i in range(36):
	state.solver.add( Claripy.Or(*(
		user_data.get_byte(i) == x for x in printable)
	))

simgr = proj.factory.simgr(state, veritesting=True)
```

# Callable State

```python
print_flag_addr = proj.loader.find_symbol("print_flag").rebased_addr
print_flag = proj.factory.callable(print_flag_addr)
print_flag(0x824, 0x82c, 0x82b, 0x82c)

# In IPython
print_flag.result_state.posix.stdout.contretize()
```

# Hook an instruction using python replacement

```python
proj.hook(<addr>, my_func, length = <length_of_the_ins>)
```
# ACI C&C Music Factory

Get the libmusiclibrary.so first

Need to do 2 callables and specify state of 2nd callable to end state of 1st callable.



```python
def perfunc_check(state):
	check_func = state.regs.rdx
	if not check_func.concrete:
		hook(locals())
	check_func = state.solver.eval_one(check_func)
	print("Perform_check with rdx={:016x}".format(check_func))
	ret_val = claripy.BVS('ret_val_{:016x}'.format(check_func), 8*8)
	state.regs.rax = ret_val
	colelction = state.globals.get('return_values', []).copy()
	collection.append(ret_val)
	state.globals['return_values'] = collection
	if check_func == rebase(<adr>):
		state.solver.add(
			ret_val == 0x11
		)
	else:
	hook(locals())
```

We are using these ret values for input via gdb