import { Outlet, NavLink } from 'react-router-dom'

export default function App() {
  return (
    <div className="app">
      <header className="header">
        <h1>CyberSentinel Evolver</h1>
        <nav>
          <NavLink to="/" end className={({ isActive }) => isActive ? 'active' : ''}>
            Dashboard
          </NavLink>
          <NavLink to="/scenarios" className={({ isActive }) => isActive ? 'active' : ''}>
            Scenarios
          </NavLink>
          <NavLink to="/tournaments" className={({ isActive }) => isActive ? 'active' : ''}>
            Tournaments
          </NavLink>
        </nav>
      </header>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
