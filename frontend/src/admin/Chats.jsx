import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

export default function Chats() {
  const [chats, setChats] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_BASE}/api/chat/admin`, {
      headers: {
        Authorization: `Bearer ${localStorage.getItem("adminToken")}`,
      },
    })
      .then((res) => {
        if (!res.ok) throw new Error("Unauthorized");
        return res.json();
      })
      .then((data) => {
        if (Array.isArray(data)) {
          setChats(data);
        } else {
          setChats([]);
        }
      })
      .catch(() => setChats([]));
  }, []);

  return (
    <div style={{ padding: 30 }}>
      <h2>Support Chats</h2>

      {chats.length === 0 && (
        <p style={{ color: "#777", marginTop: 20 }}>No support chats yet.</p>
      )}

      {chats.map((chat) => (
        <div
          key={chat._id}
          style={styles.card}
          onClick={() => navigate(`/admin/chats/${chat._id}`)}
        >
          <strong>{chat.user?.name}</strong>
          <p>{chat.user?.email}</p>
          <small>User ID: {chat.user?._id}</small>
          <p>Messages: {chat.messages?.length || 0}</p>
        </div>
      ))}
    </div>
  );
}

const styles = {
  card: {
    padding: 16,
    border: "1px solid #eee",
    borderRadius: 14,
    marginBottom: 12,
    cursor: "none",
    transition: "background 0.2s ease",
  },
};
