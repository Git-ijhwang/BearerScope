import { Component } from "react";

/** Shows the render error on screen instead of leaving a blank window */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error(error, info.componentStack);
    this.setState({ stack: info.componentStack });
  }

  render() {
    const { error, stack } = this.state;
    if (!error) return this.props.children;
    return (
      <div style={{ padding: 24, fontFamily: "IBM Plex Mono, monospace", fontSize: 12.5 }}>
        <h2 style={{ fontFamily: "IBM Plex Sans, sans-serif", fontSize: 18, color: "var(--danger)" }}>
          Something broke while drawing this screen
        </h2>
        <pre style={{ whiteSpace: "pre-wrap", color: "var(--ink)" }}>{String(error?.stack || error)}</pre>
        {stack && (
          <pre style={{ whiteSpace: "pre-wrap", color: "var(--ink-3)" }}>{stack}</pre>
        )}
        <button className="btn btn-sm btn-outline-secondary" onClick={() => this.setState({ error: null, stack: null })}>
          Try again
        </button>
      </div>
    );
  }
}
