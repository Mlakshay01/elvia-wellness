import { useEffect, useState } from "react";
import { useEditor, EditorContent } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import AdminLayout from "./AdminLayout";

const API = import.meta.env.VITE_API_BASE;
const empty = {
  title: "",
  slug: "",
  excerpt: "",
  content: "",
  coverImage: "",
  tags: "",
  published: false,
};

function RichEditor({ content, onChange }) {
  const editor = useEditor({
    extensions: [StarterKit],
    content,
    onUpdate: ({ editor }) => onChange(editor.getHTML()),
  });

  useEffect(() => {
    if (editor && content !== editor.getHTML()) {
      editor.commands.setContent(content || "");
    }
  }, [content]);

  if (!editor) return null;

  const btn = (label, action, active) => (
    <button
      key={label}
      onClick={action}
      style={{
        padding: "4px 10px",
        borderRadius: 6,
        fontSize: 13,
        cursor: "none",
        border: "1px solid #ddd",
        background: active ? "#111" : "#fff",
        color: active ? "#fff" : "#111",
      }}
    >
      {label}
    </button>
  );

  return (
    <div
      style={{
        border: "1px solid #ddd",
        borderRadius: 10,
        overflow: "hidden",
        marginTop: 6,
      }}
    >
      <div
        style={{
          display: "flex",
          gap: 4,
          padding: "8px 12px",
          borderBottom: "1px solid #eee",
          background: "#fafafa",
          flexWrap: "wrap",
        }}
      >
        {btn(
          "B",
          () => editor.chain().focus().toggleBold().run(),
          editor.isActive("bold"),
        )}
        {btn(
          "I",
          () => editor.chain().focus().toggleItalic().run(),
          editor.isActive("italic"),
        )}
        {btn(
          "H1",
          () => editor.chain().focus().toggleHeading({ level: 1 }).run(),
          editor.isActive("heading", { level: 1 }),
        )}
        {btn(
          "H2",
          () => editor.chain().focus().toggleHeading({ level: 2 }).run(),
          editor.isActive("heading", { level: 2 }),
        )}
        {btn(
          "H3",
          () => editor.chain().focus().toggleHeading({ level: 3 }).run(),
          editor.isActive("heading", { level: 3 }),
        )}
        {btn(
          "• List",
          () => editor.chain().focus().toggleBulletList().run(),
          editor.isActive("bulletList"),
        )}
        {btn(
          "1. List",
          () => editor.chain().focus().toggleOrderedList().run(),
          editor.isActive("orderedList"),
        )}
        {btn(
          "❝",
          () => editor.chain().focus().toggleBlockquote().run(),
          editor.isActive("blockquote"),
        )}
        {btn(
          "—",
          () => editor.chain().focus().setHorizontalRule().run(),
          false,
        )}
        {btn("↩ Undo", () => editor.chain().focus().undo().run(), false)}
        {btn("↪ Redo", () => editor.chain().focus().redo().run(), false)}
      </div>
      <EditorContent
        editor={editor}
        style={{ padding: 16, minHeight: 300, fontSize: 15, lineHeight: 1.8 }}
      />
    </div>
  );
}

export default function AdminBlogs() {
  const [blogs, setBlogs] = useState([]);
  const [form, setForm] = useState(empty);
  const [editingId, setEditingId] = useState(null);
  const [view, setView] = useState("list");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const token = localStorage.getItem("adminToken");
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };

  useEffect(() => {
    fetchBlogs();
  }, []);

  async function fetchBlogs() {
    const res = await fetch(`${API}/api/blogs/admin/all`, { headers });
    const data = await res.json();
    setBlogs(data);
    setLoading(false);
  }

  function openNew() {
    setForm(empty);
    setEditingId(null);
    setView("editor");
  }

  function openEdit(blog) {
    setForm({ ...blog, tags: blog.tags?.join(", ") || "" });
    setEditingId(blog._id);
    setView("editor");
  }

  async function save() {
    setSaving(true);
    const payload = {
      ...form,
      tags: form.tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    };

    const res = await fetch(
      editingId ? `${API}/api/blogs/${editingId}` : `${API}/api/blogs`,
      {
        method: editingId ? "PUT" : "POST",
        headers,
        body: JSON.stringify(payload),
      },
    );

    if (res.ok) {
      await fetchBlogs();
      setView("list");
    } else {
      const err = await res.json();
      alert(err.error || "Save failed");
    }
    setSaving(false);
  }

  async function deleteBlog(id) {
    if (!confirm("Delete this blog?")) return;
    await fetch(`${API}/api/blogs/${id}`, { method: "DELETE", headers });
    fetchBlogs();
  }

  if (loading)
    return (
      <AdminLayout>
        <p style={{ padding: 40 }}>Loading…</p>
      </AdminLayout>
    );

  return (
    <AdminLayout>
      <div style={s.page}>
        {view === "list" && (
          <>
            <div style={s.headerRow}>
              <div>
                <h1 style={s.heading}>Blogs</h1>
                <p style={s.sub}>Manage your blog posts</p>
              </div>
              <button style={s.primaryBtn} onClick={openNew}>
                + New Blog
              </button>
            </div>

            {blogs.length === 0 ? (
              <p style={{ color: "#999" }}>
                No blogs yet. Create your first one.
              </p>
            ) : (
              <div style={s.tableWrap}>
                <table style={s.table}>
                  <thead>
                    <tr>
                      <th style={s.th}>Title</th>
                      <th style={s.th}>Slug</th>
                      <th style={s.th}>Status</th>
                      <th style={s.th}>Date</th>
                      <th style={s.th}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blogs.map((blog) => (
                      <tr key={blog._id} style={s.tr}>
                        <td style={s.td}>{blog.title}</td>
                        <td style={s.td}>
                          <code style={s.code}>{blog.slug}</code>
                        </td>
                        <td style={s.td}>
                          <span style={blog.published ? s.published : s.draft}>
                            {blog.published ? "Published" : "Draft"}
                          </span>
                        </td>
                        <td style={s.td}>
                          {new Date(blog.createdAt).toLocaleDateString()}
                        </td>
                        <td style={s.td}>
                          <button
                            style={s.editBtn}
                            onClick={() => openEdit(blog)}
                          >
                            Edit
                          </button>
                          <button
                            style={s.deleteBtn}
                            onClick={() => deleteBlog(blog._id)}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {view === "editor" && (
          <>
            <div style={s.headerRow}>
              <div>
                <h1 style={s.heading}>
                  {editingId ? "Edit Blog" : "New Blog"}
                </h1>
              </div>
              <button style={s.ghostBtn} onClick={() => setView("list")}>
                ← Back
              </button>
            </div>

            <div style={s.editorWrap}>
              <div style={s.formGrid}>
                <div style={s.field}>
                  <label style={s.label}>Title</label>
                  <input
                    style={s.input}
                    value={form.title}
                    onChange={(e) =>
                      setForm({ ...form, title: e.target.value })
                    }
                  />
                </div>

                <div style={s.field}>
                  <label style={s.label}>Slug</label>
                  <input
                    style={s.input}
                    value={form.slug}
                    placeholder="my-blog-post"
                    onChange={(e) => setForm({ ...form, slug: e.target.value })}
                  />
                </div>

                <div style={{ ...s.field, gridColumn: "1 / -1" }}>
                  <label style={s.label}>Excerpt</label>
                  <textarea
                    style={s.textarea}
                    rows={2}
                    value={form.excerpt}
                    onChange={(e) =>
                      setForm({ ...form, excerpt: e.target.value })
                    }
                  />
                </div>

                <div style={s.field}>
                  <label style={s.label}>Cover Image URL</label>
                  <input
                    style={s.input}
                    value={form.coverImage}
                    onChange={(e) =>
                      setForm({ ...form, coverImage: e.target.value })
                    }
                  />
                </div>

                <div style={s.field}>
                  <label style={s.label}>Tags (comma separated)</label>
                  <input
                    style={s.input}
                    value={form.tags}
                    placeholder="wellness, skincare"
                    onChange={(e) => setForm({ ...form, tags: e.target.value })}
                  />
                </div>
              </div>

              <div style={s.field}>
                <label style={s.label}>Content</label>
                <RichEditor
                  content={form.content}
                  onChange={(val) => setForm((f) => ({ ...f, content: val }))}
                />
              </div>

              <div style={s.publishRow}>
                <label
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    cursor: "none",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={form.published}
                    onChange={(e) =>
                      setForm({ ...form, published: e.target.checked })
                    }
                  />
                  <span style={{ fontSize: 14 }}>Published</span>
                </label>

                <button style={s.primaryBtn} onClick={save} disabled={saving}>
                  {saving
                    ? "Saving…"
                    : editingId
                      ? "Update Blog"
                      : "Publish Blog"}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </AdminLayout>
  );
}

const s = {
  page: { padding: 40, fontFamily: "Inter, sans-serif" },
  headerRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 32,
  },
  heading: { fontSize: 28, fontWeight: 500, marginBottom: 4 },
  sub: { fontSize: 14, color: "#666" },
  tableWrap: {
    background: "#fff",
    borderRadius: 14,
    border: "1px solid #eee",
    overflowX: "auto",
  },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 14 },
  th: {
    padding: "14px 16px",
    textAlign: "left",
    fontSize: 12,
    color: "#999",
    borderBottom: "1px solid #eee",
    fontWeight: 500,
  },
  td: { padding: "14px 16px", borderBottom: "1px solid #f5f5f5" },
  tr: { transition: "background .15s" },
  code: {
    background: "#f5f5f5",
    padding: "2px 6px",
    borderRadius: 4,
    fontSize: 12,
  },
  published: {
    background: "#e6f4ea",
    color: "#2d7a3a",
    padding: "3px 10px",
    borderRadius: 20,
    fontSize: 12,
  },
  draft: {
    background: "#f5f5f5",
    color: "#888",
    padding: "3px 10px",
    borderRadius: 20,
    fontSize: 12,
  },
  editBtn: {
    marginRight: 8,
    padding: "6px 14px",
    borderRadius: 8,
    border: "1px solid #ddd",
    background: "#fff",
    cursor: "none",
    fontSize: 13,
  },
  deleteBtn: {
    padding: "6px 14px",
    borderRadius: 8,
    border: "1px solid #fdd",
    background: "#fff5f5",
    color: "#c62828",
    cursor: "none",
    fontSize: 13,
  },
  primaryBtn: {
    padding: "12px 24px",
    borderRadius: 12,
    border: "none",
    background: "#111",
    color: "#fff",
    cursor: "none",
    fontSize: 14,
  },
  ghostBtn: {
    padding: "10px 20px",
    borderRadius: 10,
    border: "1px solid #ddd",
    background: "#fff",
    cursor: "none",
    fontSize: 14,
  },
  editorWrap: {
    background: "#fff",
    borderRadius: 16,
    border: "1px solid #eee",
    padding: "32px 20px",
    display: "flex",
    flexDirection: "column",
    gap: 24,
    minWidth: 0,
    overflow: "hidden",
    boxSizing: "border-box",
    width: "100%",
  },
  formGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", // ← responsive columns
    gap: 20,
    minWidth: 0,
  },
  field: { display: "flex", flexDirection: "column" },
  label: { fontSize: 13, color: "#555", marginBottom: 6, fontWeight: 500 },
  input: {
    padding: "10px 14px",
    borderRadius: 10,
    border: "1px solid #ddd",
    fontSize: 14,
    width: "100%",
    boxSizing: "border-box",
  },

  textarea: {
    padding: "10px 14px",
    borderRadius: 10,
    border: "1px solid #ddd",
    fontSize: 14,
    resize: "vertical",
    width: "100%",
    boxSizing: "border-box",
  },
  publishRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    paddingTop: 16,
    borderTop: "1px solid #eee",
  },
};
