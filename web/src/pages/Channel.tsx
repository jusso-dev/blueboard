import { useSearchParams } from "react-router";
import { Feed } from "../components/feed";
import { PageHeader } from "../components/shell";
import { useLiveQuery, type Channel } from "../lib/api";

export default function ChannelPage() {
  const [params] = useSearchParams();
  const channel = params.get("channel") ?? "incidents";
  const { data: channels } = useLiveQuery<Channel[]>("/channels");
  const topic = channels?.find((c) => c.name === channel)?.topic;
  return (
    <>
      <PageHeader title={<><span className="text-faint">#</span> {channel}</>} sub={topic} />
      <Feed
        query={`channel=${encodeURIComponent(channel)}&roots_only=true`}
        composer={{ channel, placeholder: `Message #${channel}` }}
        emptyTitle={`Nothing in #${channel} yet`}
      />
    </>
  );
}
