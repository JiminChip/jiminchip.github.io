---
layout: post
title: Can you hear me?
date: April 11, 2024
categories: CTF
comment: true
---
**상위 포스트 -** [Hack The Drone 2024](/2024-09/Hack_The_Drone)

`fm_radio.iq`파일이 제공됩니다.

목표는 iq 파일을 이용하여 94.1 MHz 채널의 데이터를 듣는 것입니다. GNU Radio를 이용하여 해당 작업을 수행했습니다.

![image.png](/CTF/HackTheDrone/Can%20you%20hear%20me/image.png)

IQ 파일의 입력에서 `Frequency Xlating FIR Filter`블럭을 이용하여 94.1MHz 주파수 근방의 데이터들만 필터링합니다. 이후 `WBFM Receive` 블럭을 이용하여  FM 신호를 받아들이고, 이를 복조하여 실수형 오디오 신호로 변환합니다. 마지막으로 `Audio Sink` 블럭으로 해당 오디오를 들을 수 있도록 하고, `Wav File Sink`를 이용해 해당 오디오를 .wav 확장자 파일로 export합니다.

이 결과로 다음의 wav 파일을 얻을 수 있었습니다.

[result.wav](/CTF/HackTheDrone/Can%20you%20hear%20me/result.wav)

들어 보면, 

`Congratulations. The Flag is fm radio broadcasts good music. All words in the flag are connected with underscores, and all characters are lowercase. Also convert all o's to 0s.` 라고 들립니다. wav에서는 살짝 잘리지만 `Audio Sink` 블럭에서는 풀버전으로 들을 수 있었습니다.

flag: `HTD{fm_radi0_br0adcasts_g00d_music}`