/*
 * NullGate — LLVM 18 Compiler Instrumentation & Gadget Elimination Pass Header
 * Pillar 4: Gadget Elimination & Static Binary Sanitization
 */

#ifndef NULLGATE_LLVM_PASS_H
#define NULLGATE_LLVM_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"

namespace nullgate {

/**
 * NullGatePass - LLVM 18 Module Pass enforcing Pillar 4 invariants:
 *   1. Zero tolerance for WRPKRU in inline assembly.
 *   2. Rejection of compiler target intrinsics (llvm.x86.wrpkru).
 *   3. Enforced call-gate routing on functions with __attribute__((annotate("nullgate_domain"))).
 *   4. Control-Flow Enforcement (Intel CET) verification.
 */
class NullGatePass : public llvm::PassInfoMixin<NullGatePass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);

    /* Enforce pass execution even at -O0 */
    static bool isRequired() { return true; }

private:
    /* Scans inline assembly instructions for forbidden WRPKRU opcode strings */
    bool scanInlineAsm(llvm::Instruction *I, llvm::InlineAsm *IA);

    /* Scans call instructions for target intrinsics (e.g. llvm.x86.wrpkru) */
    bool scanIntrinsics(llvm::Instruction *I, llvm::CallInst *CI);

    /* Verifies that functions annotated with nullgate_domain use call-gate routing */
    bool verifyDomainAnnotations(llvm::Function &F);

    /* Instruments cross-compartment call-gate boundaries for CET stack alignment */
    bool instrumentCallGates(llvm::Function &F);

    /* Emits precise compile-time diagnostics identifying source file, line, and column */
    void emitCompilationError(llvm::Instruction *I, const llvm::Twine &Msg);
};

} // namespace nullgate

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo();

#endif // NULLGATE_LLVM_PASS_H
