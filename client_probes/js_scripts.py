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