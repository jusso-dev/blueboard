import { Link } from "react-router";
import { PageHeader } from "../components/shell";
import { Empty } from "../components/ui";

export default function NotFound() {
  return (
    <>
      <PageHeader title="Not found" />
      <Empty title="There's nothing at this address">
        <Link to="/" className="text-accent underline-offset-4 hover:underline">
          Back to the board
        </Link>
      </Empty>
    </>
  );
}
