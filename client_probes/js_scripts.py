PROBE_JS_SCRIPT: str = """
async function runBotProbes() {
    const payload = {
        user_agent: navigator.userAgent,
        webdriver_flag: Boolean(navigator.webdriver),
        plugins_length: navigator.plugins ? navigator.plugins.length : 0,
        languages: Array.from(navigator.languages || []),
        hardware_concurrency: navigator.hardwareConcurrency || 0,
        device_memory: navigator.deviceMemory || null,
        webgl: {
            vendor: '',
            renderer: '',
            unmasked_vendor: '',
            unmasked_renderer: '',
            gl_version: '',
            shading_language_version: '',
            extensions_count: 0
        },
        audio: {
            sample_rate: 0,
            state: '',
            max_channel_count: 0,
            oscillator_hash: ''
        },
        canvas: {
            geometry_hash: '',
            text_hash: '',
            is_canvas_tainted: false,
            noise_detected: false
        },
        worker_check: {
            worker_supported: true,
            user_agent_match: true,
            hardware_concurrency_match: true,
            languages_match: true,
            worker_user_agent: '',
            worker_concurrency: 0,
            worker_languages: []
        },
        cdp_check: {
            runtime_enable_leaks: false,
            cdc_markers_found: [],
            stack_trace_anomaly: false,
            native_fn_tampered: false
        }
    };

    try {
        const cdcProps = Object.getOwnPropertyNames(window).filter(p => p.startsWith('cdc_') || p.startsWith('$cdc_') || p.startsWith('__webdriver'));
        payload.cdp_check.cdc_markers_found = cdcProps;

        const dummyErr = new Error('cdp_probe');
        let stackModified = false;
        Object.defineProperty(dummyErr, 'stack', {
            get: function() {
                stackModified = true;
                return '';
            }
        });
        console.debug(dummyErr);
        payload.cdp_check.runtime_enable_leaks = stackModified;

        const stackCheckErr = new Error('stack_leak');
        const stackStr = String(stackCheckErr.stack || '');
        const leakTokens = ['__playwright', '__puppeteer', 'UtilityScript', 'pptr:'];
        if (leakTokens.some(token => stackStr.includes(token))) {
            payload.cdp_check.stack_trace_anomaly = true;
        }

        const nativeToString = Function.prototype.toString.call(Function.prototype.toString);
        if (!nativeToString.includes('[native code]')) {
            payload.cdp_check.native_fn_tampered = true;
        }
    } catch (e) {}

    try {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 50;
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            payload.webgl.vendor = gl.getParameter(gl.VENDOR) || '';
            payload.webgl.renderer = gl.getParameter(gl.RENDERER) || '';
            payload.webgl.gl_version = gl.getParameter(gl.VERSION) || '';
            payload.webgl.shading_language_version = gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '';

            const dbgRenderInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (dbgRenderInfo) {
                payload.webgl.unmasked_vendor = gl.getParameter(dbgRenderInfo.UNMASKED_VENDOR_WEBGL) || '';
                payload.webgl.unmasked_renderer = gl.getParameter(dbgRenderInfo.UNMASKED_RENDERER_WEBGL) || '';
            }
            const exts = gl.getSupportedExtensions();
            payload.webgl.extensions_count = exts ? exts.length : 0;
        }
    } catch (e) {}

    try {
        const c2d = document.createElement('canvas');
        c2d.width = 150;
        c2d.height = 30;
        const ctx = c2d.getContext('2d');
        if (ctx) {
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('AntiBot Prober %$#@!', 2, 2);
            payload.canvas.text_hash = c2d.toDataURL().slice(-32);

            const snap1 = c2d.toDataURL();
            const snap2 = c2d.toDataURL();
            if (snap1 !== snap2) {
                payload.canvas.noise_detected = true;
            }
        }

        const gCanvas = document.createElement('canvas');
        gCanvas.width = 120;
        gCanvas.height = 60;
        const gCtx = gCanvas.getContext('2d');
        if (gCtx) {
            gCtx.fillStyle = '#f60';
            gCtx.fillRect(10, 10, 40, 20);
            gCtx.beginPath();
            gCtx.arc(60, 30, 18, 0, Math.PI * 2, true);
            gCtx.closePath();
            gCtx.fillStyle = '#069';
            gCtx.fill();
            payload.canvas.geometry_hash = gCanvas.toDataURL().slice(-32);
        }
    } catch (e) {}

    try {
        const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (AudioCtx) {
            const audioCtx = new AudioCtx(1, 44100, 44100);
            payload.audio.sample_rate = audioCtx.sampleRate || 0;
            payload.audio.state = audioCtx.state || '';
            payload.audio.max_channel_count = audioCtx.destination ? audioCtx.destination.maxChannelCount : 0;

            const oscillator = audioCtx.createOscillator();
            oscillator.type = 'triangle';
            oscillator.frequency.setValueAtTime(10000, audioCtx.currentTime);

            const compressor = audioCtx.createDynamicsCompressor();
            compressor.threshold.setValueAtTime(-50, audioCtx.currentTime);
            compressor.knee.setValueAtTime(40, audioCtx.currentTime);
            compressor.ratio.setValueAtTime(12, audioCtx.currentTime);
            compressor.attack.setValueAtTime(0, audioCtx.currentTime);
            compressor.release.setValueAtTime(0.25, audioCtx.currentTime);

            oscillator.connect(compressor);
            compressor.connect(audioCtx.destination);
            oscillator.start(0);

            const renderPromise = audioCtx.startRendering();
            const timeoutPromise = new Promise((resolve) => setTimeout(() => resolve(null), 400));
            const renderedBuffer = await Promise.race([renderPromise, timeoutPromise]);

            if (renderedBuffer) {
                const channelData = renderedBuffer.getChannelData(0);
                let sum = 0;
                for (let i = 4500; i < 5000; i++) {
                    sum += Math.abs(channelData[i]);
                }
                payload.audio.oscillator_hash = sum.toFixed(10);
            }
        }
    } catch (e) {}

    try {
        const workerBlob = new Blob([`
            self.onmessage = function() {
                self.postMessage({
                    ua: navigator.userAgent,
                    concurrency: navigator.hardwareConcurrency,
                    languages: Array.from(navigator.languages || [])
                });
            };
        `], { type: 'application/javascript' });

        const workerUrl = URL.createObjectURL(workerBlob);
        const worker = new Worker(workerUrl);

        const workerPromise = new Promise((resolve) => {
            const timer = setTimeout(() => {
                worker.terminate();
                resolve(null);
            }, 500);

            worker.onmessage = function(ev) {
                clearTimeout(timer);
                worker.terminate();
                URL.revokeObjectURL(workerUrl);
                resolve(ev.data);
            };
        });

        worker.postMessage('ping');
        const workerData = await workerPromise;

        if (workerData) {
            payload.worker_check.worker_user_agent = workerData.ua;
            payload.worker_check.worker_concurrency = workerData.concurrency;
            payload.worker_check.worker_languages = workerData.languages;

            payload.worker_check.user_agent_match = (workerData.ua === payload.user_agent);
            payload.worker_check.hardware_concurrency_match = (workerData.concurrency === payload.hardware_concurrency);
            payload.worker_check.languages_match = (JSON.stringify(workerData.languages) === JSON.stringify(payload.languages));
        }
    } catch (e) {
        payload.worker_check.worker_supported = false;
    }

    return payload;
}
"""