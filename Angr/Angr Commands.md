
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
```