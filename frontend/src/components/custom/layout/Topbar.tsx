import { SearchInput } from "@/components/custom/Search-input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export default function Topbar() {
  return (
    <div className="sticky top-0 z-10 w-full h-16 bg-background text-white flex gap-12 items-center px-4">
        <h1 className="text-lg font-heading font-bold">
            Q-Ready
        </h1>
        <div>
            <SearchInput />
        </div>
        <Button>
            <div className="flex flex-row items-center">
                Click me
            </div>
        </Button>
        <div className="flex w-full flex-wrap justify-center gap-2">
            <Badge className="bg-severity-critical text-red-300">Critical</Badge>
            <Badge className="bg-severity-high text-red-400">High</Badge>
            <Badge className="bg-severity-medium text-orange-300">Medium</Badge>
            <Badge className="bg-severity-low text-green-400">Low</Badge>
        </div>
    </div>
  );
}