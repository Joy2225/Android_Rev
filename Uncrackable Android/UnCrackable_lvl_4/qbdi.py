import pyqbdi
import ctypes
import sys

def printInstruction(vm, gpr, fpr, data):
    inst = vm.getInstAnalysis()
    print("0x{} {}".format(inst.address, inst.disassembly))
    return pyqbdi.CONTINUE

def run():
    vm = pyqbdi.VM()
    state = vm.getGPRState()
    success, addr = pyqbdi.allocateVirtualStack(state, 0x100000)
    aLib = ctypes.cdll.LoadLibrary("./Release/r2pay-v1.0/lib/x86_64/libnative-lib.so")
    funcPtr = ctypes.cast(aLib.aFunction, ctypes.c_void_p).value
    vm.addInstrumentedModuleFromAddr(funcPtr)
    vm.addCodeCB(pyqbdi.PREINST, printInstruction, None)
    vm.call(funcPtr, [42])