interface ProgressBarProps {
  current: number;
  target: number;
}

export function ProgressBar({ current, target }: ProgressBarProps): JSX.Element {
  const percent = target > 0 ? Math.min((current / target) * 100, 100) : 0;

  return (
    <div>
      <div className="progress-meta">
        <span>{current} signatures</span>
        <span>{target > 0 ? `Target ${target}` : 'No target set'}</span>
      </div>
      <div className="progress-track" role="progressbar" aria-valuenow={Math.round(percent)} aria-valuemin={0} aria-valuemax={100}>
        <div className="progress-fill" style={{ width: `${percent}%` }} />
      </div>
      {target > 0 && current >= target ? <p className="progress-note">Target achieved. Signatures are still accepted.</p> : null}
    </div>
  );
}
