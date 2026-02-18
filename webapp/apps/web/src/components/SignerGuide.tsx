import { useEffect, useState } from 'react';
import { CheckCircle2, Download, ExternalLink, FileCheck2, Link2, ShieldCheck } from 'lucide-react';

import { getDownloads } from '../api';
import type { DownloadBinary, DownloadsResponse } from '../types';

type ClientPlatform = {
  os: 'windows' | 'macos' | 'linux' | 'unknown';
  arch: 'amd64' | 'arm64' | 'unknown';
};

function detectClientPlatform(): ClientPlatform {
  const nav = navigator as Navigator & {
    userAgentData?: {
      platform?: string;
      architecture?: string;
    };
  };

  const ua = navigator.userAgent.toLowerCase();
  const platform = `${navigator.platform} ${nav.userAgentData?.platform ?? ''}`.toLowerCase();
  const archRaw = `${nav.userAgentData?.architecture ?? ''} ${ua}`.toLowerCase();

  let os: ClientPlatform['os'] = 'unknown';
  if (platform.includes('win') || ua.includes('windows')) {
    os = 'windows';
  } else if (platform.includes('mac') || ua.includes('mac os') || ua.includes('darwin')) {
    os = 'macos';
  } else if (platform.includes('linux') || ua.includes('linux')) {
    os = 'linux';
  }

  let arch: ClientPlatform['arch'] = 'unknown';
  if (archRaw.includes('aarch64') || archRaw.includes('arm64')) {
    arch = 'arm64';
  } else if (archRaw.includes('x86_64') || archRaw.includes('x64') || archRaw.includes('amd64') || archRaw.includes('win64') || archRaw.includes('intel')) {
    arch = 'amd64';
  }

  if (os === 'windows' || os === 'linux') {
    arch = 'amd64';
  }

  return { os, arch };
}

function binaryKey(binary: DownloadBinary): string {
  const os = binary.os.toLowerCase().includes('windows')
    ? 'windows'
    : binary.os.toLowerCase().includes('mac')
      ? 'macos'
      : binary.os.toLowerCase().includes('linux')
        ? 'linux'
        : 'unknown';
  const arch = binary.arch.toLowerCase().includes('apple') || binary.arch.toLowerCase().includes('arm')
    ? 'arm64'
    : binary.arch.toLowerCase().includes('intel') || binary.arch.toLowerCase().includes('x64')
      ? 'amd64'
      : 'unknown';
  return `${os}:${arch}`;
}

export function SignerGuide(): JSX.Element {
  const [downloads, setDownloads] = useState<DownloadsResponse | null>(null);
  const [downloadsError, setDownloadsError] = useState('');
  const [recommendedKey, setRecommendedKey] = useState<string>('');

  useEffect(() => {
    const p = detectClientPlatform();
    setRecommendedKey(`${p.os}:${p.arch}`);
  }, []);

  useEffect(() => {
    getDownloads()
      .then(setDownloads)
      .catch((err: unknown) => setDownloadsError(err instanceof Error ? err.message : 'Could not load download links'));
  }, []);

  const binaries = (downloads?.binaries ?? []).slice().sort((a, b) => {
    const aRecommended = binaryKey(a) === recommendedKey;
    const bRecommended = binaryKey(b) === recommendedKey;
    if (aRecommended === bRecommended) {
      return 0;
    }
    return aRecommended ? -1 : 1;
  });

  return (
    <section className="guide-card">
      <h3>How to participate as a signer</h3>
      <p>Use Vocsign desktop app to read the proposal request, review legal text, and submit your qualified signature.</p>
      <ol className="steps">
        <li>
          <Download size={16} />
          <span>Download Vocsign for your operating system.</span>
        </li>
        <li>
          <ShieldCheck size={16} />
          <span>Open Vocsign and import your valid certificate if needed.</span>
        </li>
        <li>
          <Link2 size={16} />
          <span>Open Vocsign and paste the proposal signing URL.</span>
        </li>
        <li>
          <FileCheck2 size={16} />
          <span>Review proposal title, summary and legal statement before signing.</span>
        </li>
        <li>
          <CheckCircle2 size={16} />
          <span>Confirm signature. Your signature count appears on this page immediately.</span>
        </li>
      </ol>
      <div className="download-grid">
        {binaries.map((binary) => {
          const recommended = binaryKey(binary) === recommendedKey;
          return (
            <a
              key={binary.id}
              className={`btn btn-secondary ${recommended ? 'btn-recommended' : ''}`}
              href={binary.url}
              target="_blank"
              rel="noreferrer"
            >
              <Download size={15} />
              {binary.os} ({binary.arch})
              {recommended ? <span className="recommended-pill">Recommended</span> : null}
            </a>
          );
        })}
      </div>
      {downloadsError ? <p className="error-box">{downloadsError}</p> : null}
      <p className="meta">
        Vocsign source code is open source under GPLv3 and can be inspected by anyone on{' '}
        <a href="https://github.com/vocdoni/vocsign" target="_blank" rel="noreferrer">
          GitHub <ExternalLink size={14} />
        </a>
        .
      </p>
    </section>
  );
}
