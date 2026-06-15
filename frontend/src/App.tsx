import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Sidebar from './components/custom/layout/Sidebar'
import Topbar from './components/custom/layout/Topbar'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import Import from './pages/Import'
import Lab from './pages/Lab'

const queryClient = new QueryClient()

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="flex flex-row h-screen">
          <Sidebar />
          <div className="flex-1 flex flex-col bg-background overflow-hidden">
            <Topbar />
            <main className="flex-1 overflow-auto">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/import" element={<Import />} />
                <Route path="/lab" element={<Lab />} />
              </Routes>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
