import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Badge } from '../Badge';
import { RiskBadge } from '../RiskBadge';
import { SeverityBadge } from '../SeverityBadge';
import { StatusPill } from '../StatusPill';

describe('Badge', () => {
  it('renders its children', () => {
    render(<Badge>Draft</Badge>);
    expect(screen.getByText('Draft')).toBeInTheDocument();
  });

  it('draws the accent as a left rule rather than tinting the text', () => {
    render(<Badge accentColor="#8c1d18">Critical</Badge>);
    expect(screen.getByText('Critical')).toHaveStyle({ borderLeftColor: '#8c1d18' });
  });

  it('exposes an extra label to assistive tech when asked', () => {
    render(<Badge srLabel="Risk band">High</Badge>);
    expect(screen.getByText('Risk band')).toBeInTheDocument();
  });
});

describe('RiskBadge', () => {
  it.each([
    ['CRITICAL', 'Critical'],
    ['HIGH', 'High'],
    ['MEDIUM', 'Medium'],
    ['LOW', 'Low'],
  ] as const)('always renders the text label for %s, not colour alone', (band, label) => {
    render(<RiskBadge band={band} score={72.5} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it('shows the score alongside the band', () => {
    render(<RiskBadge band="HIGH" score={72.46} />);
    // One decimal: the score is ordinal, so more precision would imply
    // a discrimination the fusion does not have.
    expect(screen.getByText('72.5')).toBeInTheDocument();
  });

  it('distinguishes "not assessed" from a low score', () => {
    render(<RiskBadge band={null} />);
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
    expect(screen.queryByText('Low')).not.toBeInTheDocument();
  });

  it('describes a LOW band as not prioritised rather than cleared', () => {
    render(<RiskBadge band="LOW" score={12} />);
    const badge = screen.getByText('Low').closest('span');
    expect(badge?.getAttribute('title')).toMatch(/not a clearance/i);
  });
});

describe('SeverityBadge', () => {
  it('renders a dash when severity is absent', () => {
    render(<SeverityBadge severity={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('labels the severity', () => {
    render(<SeverityBadge severity="MEDIUM" />);
    expect(screen.getByText('Medium')).toBeInTheDocument();
  });
});

describe('StatusPill', () => {
  it('maps a known value to its label', () => {
    render(<StatusPill kind="case" value="UNDER_INVESTIGATION" />);
    expect(screen.getByText('Under investigation')).toBeInTheDocument();
  });

  it('humanises an unknown value instead of rendering nothing', () => {
    // A state added on the backend must stay visible rather than
    // silently disappearing from the UI.
    render(<StatusPill kind="case" value="PENDING_LEGAL_REVIEW" />);
    expect(screen.getByText('Pending legal review')).toBeInTheDocument();
  });

  it('explains what a scoring mode means', () => {
    render(<StatusPill kind="scoring-mode" value="HEURISTIC_FALLBACK" />);
    const pill = screen.getByText('Heuristic fallback');
    expect(pill.getAttribute('title')).toMatch(/hand-set, not learned/i);
  });
});
