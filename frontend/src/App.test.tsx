import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import '@testing-library/jest-dom';
import App from './App';

describe('App', () => {
  it('renders the login screen initially', () => {
    render(<App />);
    expect(screen.getByText(/NetSleuth AI/i)).toBeInTheDocument();
    expect(screen.getByText(/Secure Authentication/i)).toBeInTheDocument();
  });
});
