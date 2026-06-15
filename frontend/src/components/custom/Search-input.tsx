import { Input } from "@/components/ui/input"
import { Search } from "lucide-react"

export function SearchInput() {
  return (
    <div className="relative w-full">
      <Search className="absolute left-2.5 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
      <Input className="pl-8 bg-sidebar border-[0.5px] border-sidebar-border rounded-sm" placeholder="Search inventory..." />
    </div>
  )
}
