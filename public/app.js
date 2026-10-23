/*
 * ChainProof live feed.
 *
 * The dashboard is server-rendered on purpose: every finding must survive a
 * reload because the evidence lives on disk. This script only does the two
 * things a rendered page cannot: stream events while a run is in flight, and
 * refresh the page when the state machine moves to a new structural step.
 */
(() => {
    'use strict';

    const STATUS_LABELS = {
        queued: '排队中',
        running: '运行中',
        completed: '已完成',
        failed: '失败',
        proven: '链上已验证',
        accepted: '审查通过',
        needs_manual_poc: '需人工 PoC',
        poc_failed: 'PoC 未通过',
        rejected: '审查驳回',
        candidate: '候选',
    };

    const STRUCTURAL_EVENTS = new Set([
        'attacker.finding',
        'finding.rejected',
        'finding.chain_falsified',
        'chain.proof',
        'poc.skipped',
        'poc.disabled',
        'bounty.paid',
        'bounty.failed',
        'report.ready',
    ]);

    const POLL_MS = 1500;
    const RELOAD_DEBOUNCE_MS = 1200;

    const root = document.querySelector('[data-run-id]');
    if (!root) {
        return;
    }

    const runId = root.dataset.runId;
    const initialStatus = root.dataset.status || '';
    if (initialStatus !== 'queued' && initialStatus !== 'running') {
        // Terminal state: the HTML already contains the final evidence.
        return;
    }

    const stream = document.getElementById('event-stream');
    const cliLog = document.querySelector('.cli-log');
    const badge = document.getElementById('stat-status');

    let lastSeq = 0;
    if (stream) {
        stream.querySelectorAll('[data-seq]').forEach((node) => {
            const seq = Number(node.dataset.seq);
            if (Number.isFinite(seq) && seq > lastSeq) {
                lastSeq = seq;
            }
        });
    }

    let timer = null;
    let stopped = false;
    let reloading = false;
    let lastReloadAt = 0;
    let structuralSeen = false;
    let inFlight = false;

    const schedule = () => {
        if (stopped || reloading) {
            return;
        }
        window.clearTimeout(timer);
        timer = window.setTimeout(poll, POLL_MS);
    };

    const stop = () => {
        stopped = true;
        window.clearTimeout(timer);
    };

    const reload = (delay) => {
        if (reloading) {
            return;
        }
        const wait = Math.max(delay, RELOAD_DEBOUNCE_MS - (Date.now() - lastReloadAt));
        reloading = true;
        window.clearTimeout(timer);
        timer = window.setTimeout(() => window.location.reload(), wait);
    };

    const renderStatus = (status) => {
        if (!badge || !status) {
            return;
        }
        badge.textContent = STATUS_LABELS[status] || status;
        badge.className = badge.className.replace(/badge-\S+/g, '').trim();
        badge.classList.add('badge', `badge-${status}`);
        root.dataset.status = status;
    };

    const renderStats = (stats) => {
        if (!stats) {
            return;
        }
        const values = {
            'stat-findings': stats.findings,
            'stat-proven': stats.proven,
            'stat-extracted': stats.extracted_eth,
            'stat-bounty': stats.bounty_eth,
        };
        Object.entries(values).forEach(([id, value]) => {
            const node = document.getElementById(id);
            if (node && value !== undefined && value !== null) {
                node.textContent = String(value);
            }
        });
    };

    const nearBottom = () => {
        if (!stream) {
            return true;
        }
        return stream.scrollHeight - stream.scrollTop - stream.clientHeight < 42;
    };

    const appendEvents = (events) => {
        if (!stream || !Array.isArray(events)) {
            return;
        }
        const stick = nearBottom();
        let appended = false;

        events.forEach((event) => {
            const seq = Number(event.seq);
            if (!Number.isFinite(seq) || seq <= lastSeq) {
                return;
            }
            lastSeq = seq;
            appended = true;

            const row = document.createElement('div');
            row.className = `event event-${event.level || 'info'}`;
            row.dataset.seq = String(seq);

            const time = document.createElement('span');
            time.className = 'event-time';
            const at = typeof event.at === 'string' ? event.at : '';
            time.textContent = at.length >= 19 ? at.slice(11, 19) : '';

            const type = document.createElement('span');
            type.className = 'event-type';
            type.textContent = event.type || 'event';

            const message = document.createElement('span');
            message.className = 'event-msg';
            message.textContent = event.message || '';

            row.append(time, type, message);
            stream.append(row);

            if (STRUCTURAL_EVENTS.has(event.type)) {
                structuralSeen = true;
            }
        });

        if (appended && stick) {
            stream.scrollTop = stream.scrollHeight;
        }
    };

    const renderCliLog = (text) => {
        if (!cliLog || typeof text !== 'string' || text === '') {
            return;
        }
        const stick = cliLog.scrollHeight - cliLog.scrollTop - cliLog.clientHeight < 24;
        cliLog.textContent = text;
        if (stick) {
            cliLog.scrollTop = cliLog.scrollHeight;
        }
    };

    const poll = async () => {
        if (stopped || reloading || inFlight) {
            return;
        }
        inFlight = true;
        structuralSeen = false;

        try {
            const response = await fetch(`/api/runs/${encodeURIComponent(runId)}`, {
                headers: { Accept: 'application/json' },
                cache: 'no-store',
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();

            renderStats(payload.stats);
            renderStatus(payload.run && payload.run.status);
            appendEvents(payload.events);
            renderCliLog(payload.cli_log);

            const status = payload.run && payload.run.status;
            if (status === 'completed' || status === 'failed') {
                stop();
                reload(700);
                return;
            }

            if (structuralSeen) {
                lastReloadAt = Date.now();
                reload(RELOAD_DEBOUNCE_MS);
                return;
            }
        } catch (error) {
            // A background run can briefly hold run.json while rewriting it.
            // Treat a failed poll as noise and retry on the next tick.
            if (window.console && typeof window.console.debug === 'function') {
                window.console.debug('ChainProof poll failed', error);
            }
        } finally {
            inFlight = false;
            schedule();
        }
    };

    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            window.clearTimeout(timer);
            return;
        }
        if (!stopped && !reloading) {
            window.clearTimeout(timer);
            timer = window.setTimeout(poll, 120);
        }
    });

    if (stream) {
        stream.scrollTop = stream.scrollHeight;
    }
    schedule();
})();
