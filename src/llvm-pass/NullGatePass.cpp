/*
 * NullGate — LLVM 18 Compiler Instrumentation & Gadget Elimination Pass Implementation
 * Pillar 4: Gadget Elimination & Static Binary Sanitization
 */

#include "NullGatePass.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace nullgate;

void NullGatePass::emitCompilationError(Instruction *I, const Twine &Msg)
{
    std::string LocationStr;
    raw_string_ostream OS(LocationStr);

    if (I) {
        const DebugLoc &DL = I->getDebugLoc();
        if (DL) {
            OS << DL->getFilename() << ":" << DL.getLine() << ":" << DL.getCol() << ": ";
        }
    }

    OS << "error [NullGate Pillar 4]: " << Msg;
    report_fatal_error(StringRef(OS.str()));
}

bool NullGatePass::scanInlineAsm(Instruction *I, InlineAsm *IA)
{
    if (!IA)
        return false;

    StringRef AsmString = IA->getAsmString();
    std::string LowerAsm = AsmString.lower();

    /* 1. Strictly forbid any inline assembly containing 'wrpkru' opcode */
    if (LowerAsm.find("wrpkru") != std::string::npos) {
        emitCompilationError(
            I,
            "Direct emission of 'wrpkru' instruction in inline assembly is strictly forbidden by NullGate policy."
        );
        return true;
    }

    /* 2. Directive check for raw byte emission of 0x0F, 0x01, 0xEF (Fix MED-03 & LOW-03) */
    bool has_directive = (LowerAsm.find(".byte") != std::string::npos ||
                          LowerAsm.find(".inst") != std::string::npos ||
                          LowerAsm.find(".value") != std::string::npos ||
                          LowerAsm.find(".short") != std::string::npos ||
                          LowerAsm.find(".long") != std::string::npos ||
                          LowerAsm.find(".int") != std::string::npos ||
                          LowerAsm.find(".ascii") != std::string::npos ||
                          LowerAsm.find(".asciz") != std::string::npos ||
                          LowerAsm.find(".string") != std::string::npos);

    if (has_directive) {
        bool has_0f = (LowerAsm.find("0x0f") != std::string::npos || LowerAsm.find("15") != std::string::npos ||
                       LowerAsm.find("\\x0f") != std::string::npos || LowerAsm.find("\\017") != std::string::npos ||
                       LowerAsm.find("\\17") != std::string::npos);
        bool has_01 = (LowerAsm.find("0x01") != std::string::npos || LowerAsm.find("0x1") != std::string::npos ||
                       LowerAsm.find("1") != std::string::npos || LowerAsm.find("\\x01") != std::string::npos ||
                       LowerAsm.find("\\001") != std::string::npos || LowerAsm.find("\\1") != std::string::npos);
        bool has_ef = (LowerAsm.find("0xef") != std::string::npos || LowerAsm.find("239") != std::string::npos ||
                       LowerAsm.find("\\xef") != std::string::npos || LowerAsm.find("\\357") != std::string::npos);

        if ((has_0f && has_01 && has_ef) ||
            LowerAsm.find("ef010f") != std::string::npos ||
            (LowerAsm.find("010f") != std::string::npos && has_ef) ||
            LowerAsm.find("\\x0f\\x01\\xef") != std::string::npos ||
            LowerAsm.find("\\017\\001\\357") != std::string::npos) {
            emitCompilationError(
                I,
                "Raw byte emission of 'WRPKRU' opcode (0x0F, 0x01, 0xEF) in inline assembly is strictly forbidden by NullGate policy."
            );
            return true;
        }
    }

    return false;
}

bool NullGatePass::scanIntrinsics(Instruction *I, CallInst *CI)
{
    if (!CI)
        return false;

    Function *Callee = CI->getCalledFunction();
    if (!Callee)
        return false;

    /*
     * Check 1: Target Intrinsic ID check (llvm.x86.wrpkru)
     */
    if (Callee->isIntrinsic()) {
        if (Callee->getIntrinsicID() == Intrinsic::x86_wrpkru) {
            emitCompilationError(
                I,
                "Direct invocation of 'llvm.x86.wrpkru' target intrinsic is strictly forbidden by NullGate policy."
            );
            return true;
        }
    }

    /*
     * Check 2: Callee name check for compiler-specific WRPKRU intrinsics and builtins
     */
    StringRef CalleeName = Callee->getName();
    if (CalleeName.contains("wrpkru") || CalleeName.contains("_writepkru")) {
        emitCompilationError(
            I,
            "Direct invocation of PKRU modifier function '" + CalleeName +
            "' is strictly forbidden by NullGate policy."
        );
        return true;
    }

    return false;
}

bool NullGatePass::verifyDomainAnnotations(Function &F)
{
    Module *M = F.getParent();
    if (!M)
        return false;

    GlobalVariable *GA = M->getGlobalVariable("llvm.global.annotations");
    if (!GA || !GA->hasInitializer())
        return false;

    ConstantArray *CA = dyn_cast<ConstantArray>(GA->getInitializer());
    if (!CA)
        return false;

    bool isDomainFunction = false;

    for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
        ConstantStruct *CS = dyn_cast<ConstantStruct>(CA->getOperand(i));
        if (!CS || CS->getNumOperands() < 2)
            continue;

        Value *AnnotatedVal = CS->getOperand(0)->stripPointerCasts();
        if (AnnotatedVal != &F)
            continue;

        GlobalVariable *AnnotationStrVar = dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts());
        if (!AnnotationStrVar || !AnnotationStrVar->hasInitializer())
            continue;

        ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(AnnotationStrVar->getInitializer());
        if (!CDA)
            continue;

        StringRef Annotation = CDA->getAsString();
        if (Annotation.starts_with("nullgate_domain")) {
            isDomainFunction = true;
            break;
        }
    }

    if (isDomainFunction) {
        /*
         * Verify that any direct call to this function originates from trusted dispatchers
         * or is called via ng_enter() / ng_callgate_invoke().
         */
        for (User *U : F.users()) {
            if (auto *CI = dyn_cast<CallInst>(U)) {
                Function *Caller = CI->getFunction();
                if (Caller && Caller != &F) {
                    StringRef CallerName = Caller->getName();
                    if (!CallerName.starts_with("ng_") && !CallerName.starts_with("__nullgate_")) {
                        /* Direct cross-domain invocation detected without gate */
                        emitCompilationError(
                            CI,
                            "Direct call to domain-isolated function '" + F.getName() +
                            "' from untrusted caller '" + CallerName +
                            "' is forbidden. Calls must be routed through ng_enter()."
                        );
                    }
                }
            }
        }
    }

    return isDomainFunction;
}

bool NullGatePass::instrumentCallGates(Function &F)
{
    /*
     * Validate that functions maintain Control-Flow Enforcement (Intel CET) compatibility
     */
    if (F.hasFnAttribute("no-cf-protection")) {
        emitCompilationError(
            &*F.getEntryBlock().begin(),
            "Function '" + F.getName() + "' specifies 'no-cf-protection', violating Intel CET policy."
        );
        return true;
    }

    return false;
}

PreservedAnalyses NullGatePass::run(Module &M, ModuleAnalysisManager &)
{
    for (Function &F : M) {
        if (F.isDeclaration())
            continue;

        verifyDomainAnnotations(F);
        instrumentCallGates(F);

        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (CI->isInlineAsm()) {
                        if (auto *IA = dyn_cast<InlineAsm>(CI->getCalledOperand())) {
                            scanInlineAsm(CI, IA);
                        }
                    } else {
                        scanIntrinsics(CI, CI);
                    }
                }
            }
        }
    }

    return PreservedAnalyses::all();
}

/*
 * LLVM 18 Pass Plugin Registration
 */
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION,
        "NullGatePass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            /* 1. Register for automatic execution under clang -fpass-plugin */
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                    MPM.addPass(NullGatePass());
                }
            );

            /* 2. Register for command-line pipeline parsing under opt -passes="nullgate-pass" */
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "nullgate-pass") {
                        MPM.addPass(NullGatePass());
                        return true;
                    }
                    return false;
                }
            );
        }
    };
}
