// Public client config. The anon key is meant to be public: every table is protected by RLS,
// and every write goes through role-checked database functions.
window.CARDFORGE_CONFIG = {
  supabaseUrl: "https://whgdqbplitaacpxyogfn.supabase.co",
  supabaseAnonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndoZ2RxYnBsaXRhYWNweHlvZ2ZuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTU0MjAwMTksImV4cCI6MjExMDk5NjAxOX0.ZPpfE9WY0vMqCOuYLpDNyoWfXtru7NXzg7tmBJ3WZog"
};
