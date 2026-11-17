---
title: "Weird ELF Machines (Part 4): Evaluating Reloccult"
date: 2026-11-18 00:00:00 +0900
description: Reloccult's detection results, the influence of its host binary, and why the weird machine inside the ELF dynamic linker needs attention.
read_time: 10
lang: en
image:
  path: /assets/img/post-covers/weird-elf-machines-part-1.png
  alt: Minimal ELF file and hammer illustration for the Weird ELF Machines series
  no_bg: true
categories: [Tech Articles, Reloccult]
tags: [weird-machine, elf, relocation]
comment: true
---

## Trying Reloccult on Malware

In [Part 3](https://mini-chip.kr/posts/weird-elf-machines-part-3/), I introduced Reloccult, a packer that uses ELF relocations to reconstruct a payload and launch it before the host's entry point. Because the loader does the unpacking work while processing metadata, the host's own code never gets its turn.

With the packer working, I wanted to see whether scanners would still recognize malware they already knew once it had been repackaged this way.

For that test, I used the 711 malicious x86-64 ELF samples from the EvilELF benchmark, drawn from [Labeled-Elfs](https://github.com/nimrodpar/Labeled-Elfs). I compared each original file with its UPX-packed and Reloccult-packed versions, using two benign hosts of roughly 4 MB and 12 MB for Reloccult.

All variants start from the same payload ELF while changing how it is stored and reached. UPX reconstructs it through a conventional unpacking stub; Reloccult has the dynamic linker prepare it through relocation processing. This makes UPX a useful reference for how the same tools respond to a familiar packer.

The research prototype packed all 711 samples under both hosts. Running them through the test harness on Ubuntu 24.04 with glibc 2.39 confirmed that they reconstructed their payloads and reached the `memfd`/`execveat` launch path before host entry. These were the files I then submitted to the static scanners.

## What the Scanners Saw

> **EMBER 2024**
>
> EMBER 2024 was published at [KDD 2025](https://arxiv.org/html/2506.05074v1), a top-tier conference in machine learning and data mining, and its [public models](https://huggingface.co/joyce8/EMBER2024-benchmark-models) make the experiments reproducible. I chose its ELF classifier because it performs well at detecting ELF malware and was one of the latest available models when I ran these experiments.
{: .prompt-info }

With the detection threshold set to 0.5, the model produced the following results:

| Input | Detected | Detection rate | Mean score |
| --- | ---: | ---: | ---: |
| Original malware | 686 / 711 | 96.48% | 0.9376 |
| UPX | 711 / 711 | 100% | 0.9976 |
| Reloccult, 4 MB host | 0 / 711 | 0% | 0.0070 |
| Reloccult, 12 MB host | 0 / 711 | 0% | 0.0002 |

Although the model recognized almost all the original samples and every UPX-packed sample, it flagged none of the Reloccult outputs. The mean scores also moved well below the threshold, especially with the larger host. I will come back to that difference when looking at the host's influence.

I also scanned the files with ClamAV and public YARA rule sets, then checked whether Detect It Easy recognized them as packed. These cover malware signatures, structural heuristics, and packer identification. Both Reloccult hosts gave the same rates:

| Check | Original malware | UPX | Reloccult |
| --- | ---: | ---: | ---: |
| ClamAV, default malware detection | 100% | 0% | 0% |
| YARA-Forge, full ruleset | 13.78% | 2.39% | 0% |
| Elastic, public Linux YARA rules | 41.35% | 0% | 0% |
| ClamAV, broken-executable heuristic | 100% | 100% | 0% |
| Detect It Easy, packer identification | 0% | 100% | 0% |
| Elastic siglearn, ELF rules | 46.27% | 100% | 0% |

ClamAV's default scan detected every original payload but missed both packed versions. Even so, its structural heuristic flagged all the UPX outputs, Detect It Easy recognized the UPX packer, and Elastic's ML-derived siglearn rules matched every UPX sample. None produced those signals for Reloccult.

This is why the UPX comparison matters. The tools had ways to recognize conventional packing even when their original malware signatures no longer matched. What caught my attention was that the relocation-based version did not register as packed or structurally suspicious in those checks either.

## A Different Shape of Packer

Those zeros might make Reloccult sound like an impressive concealment technique, but my first explanation is fairly ordinary: **the tools were probably not looking for this kind of packer yet.**

UPX has a recognizable shape: compressed data alongside the code that unpacks it. This gives an analyzer a familiar format to identify or an unpacking stub to follow from the entry point.

Reloccult instead describes the reconstruction work in the relocation table, with the payload bytes spread across relocation addends. As `ld.so` applies those records during loading, it assembles the payload. Launching that payload then replaces the process image before the host reaches its entry point.

The packed file has no compressed payload blob, and following the host entry point does not lead to a conventional unpacking loop. The bytes that will become the stub and payload are represented by relocation records, so following the host's instructions misses the work that reconstructs them. To explain the behavior, an analyzer also needs to account for what the loader does with those records.

## How the Host Affects the Verdict

The choice of host matters too, since a Reloccult-packed file retains much of the host's appearance, including its strings, imports, and byte patterns. While the payload sits in relocation metadata, the host still supplies much of what a static detector sees. **Even with the same payload, the verdict can therefore depend on which host carries it.**

For EMBER, whose ELF model relies on file-level byte, entropy, and string statistics, a much larger host with strong benign features can dominate the contribution from a small payload. Even after packing, the file may still look enough like the original benign program for the model to classify it that way.

The mean EMBER score points in that direction, falling from 0.0070 with the roughly 4 MB host to 0.0002 with the roughly 12 MB host. Although both were already below the detection threshold, the lower score with the larger host seems consistent with the host's features diluting the payload's signal. Alongside the unfamiliar packing format, that probably explains part of the result.

The resulting file therefore reflects a combination of payload and host. Keeping the payload fixed while changing the host can change the strings, size, and byte distribution presented to the detector. In that sense, the host is part of the explanation for why the packed file receives a benign verdict, even though the program it eventually launches has not changed.

I would expect detection to improve once tools account for these features. Reloccult leaves a large relocation table and relocations that write back into it, giving detectors patterns to learn or encode in rules. The interesting question for the rest of this series is how those ordinary-looking records acquired enough power to become a packer in the first place.

## The Weird Machine Inside the Dynamic Linker

The weird machine already exists in `ld.so`; the scanner experiment makes one practical use of it visible. The construction depends on the way the dynamic linker interprets metadata as a sequence of operations with side effects.

Relocations normally fix addresses, so the loader must write values to memory. IFUNC resolution normally selects a function implementation, so the loader can also call a resolver while processing those relocations. Reloccult combines these existing operations: early writes modify records that will be processed later, subsequent writes construct the stub and payload, and an IFUNC call transfers control to the completed stub.

Once one record can change what a later record will do, the relocation table behaves like a program with mutable instructions. The loader supplies the interpreter and memory access, while the ELF supplies the operations and their operands. That is the weird-machine behavior the earlier posts built on, and it exists independently of whether a scanner recognizes the resulting file.

The whole construction fits into a single ELF and runs through its normal interpreter path. The kernel maps the executable and its interpreter, then `ld.so` processes the metadata as part of startup. By arranging that input, Reloccult gets the dynamic linker to prepare another program and hand execution to it before the host entry point.

Full RELRO and `BIND_NOW` did not stop this path in the tested environment because it operates during the initialization work those settings still require. RELRO protects selected memory ranges after their relocations have been applied; Reloccult acts while the loader is still making those writes. Its trigger is also reached during eager relocation processing, so it does not depend on lazy PLT binding.

Antivirus can add signatures for the packed format, and EDR can observe the `memfd_create` and `execveat` activity at runtime. Alongside that work, **the dynamic linker should also constrain the behavior that makes this weird machine possible.** The ability to turn relocation metadata into a program comes from its loading semantics, and those semantics deserve attention directly.

## Constraining the Loader's Behavior

The first place I would look is writes into the metadata the loader is still interpreting. Reloccult relies on earlier relocations modifying later entries, so a policy that rejects those writes would break this particular chain. It would give the relocation table a clearer role as input to the pass, rather than allowing it to become mutable program state during that same pass.

IFUNC resolution is another place to examine. In Reloccult, the resolver call enters bytes just constructed by the relocation writes. Checking the resolver's destination and the permissions of the memory it points into could constrain that transfer. The important question for the loader is which call targets it should accept while initializing an object.

A stricter loading mode could also validate relocation destinations and dynamic-table pointers before applying them, with checks for targets outside expected ranges or tables redirected into unusual writable regions. These checks would act where the writes and calls actually happen, instead of depending on whether a scanner knows the name or signature of this packer.

These are directions to explore, rather than a completed fix. IFUNC is used for legitimate CPU-specific function selection, and binary rewriters or language runtimes can produce unusual metadata. An audit mode could help identify compatibility problems before stricter policies are enabled. The aim would be to preserve normal linking while limiting the combinations that turn it into a programmable execution environment.

## Conclusion

Starting with relocation-driven memory writes and calls in [Part 1](https://mini-chip.kr/posts/weird-elf-machines-part-1/), I combined them in [Part 2](https://mini-chip.kr/posts/weird-elf-machines-part-2/) into a program that could produce observable behavior even when the main ELF had no executable segment. Part 3 turned that idea into a packer, and this experiment shows how it can fall outside the patterns existing static tools recognize.

The detection results seem to reflect both the unfamiliar packing format and the benign host's influence on the file's features. Tools can learn to recognize those patterns. What brings me back to the dynamic linker is that `ld.so` carries out the program hidden in the metadata, using the operations it already provides for normal loading.

When that metadata can modify its own instructions, reconstruct a payload, and redirect execution before the host's entry point, I think the ELF loading model has a design problem worth revisiting. **The weird machine comes from the dynamic linker, so the dynamic linker should be part of the fix.**
