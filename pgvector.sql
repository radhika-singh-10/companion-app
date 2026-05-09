-- Reference: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase#create-a-table-and-search-function-in-your-database
-- Visit Supabase docs for more: https://supabase.com/docs/guides/ai/vector-columns
-- Enable the pgvector extension to work with embedding vectors
create extension vector;

-- Create a table to store your documents
create table documents (
  id bigserial primary key,
  content text, -- corresponds to Document.pageContent
  metadata jsonb, -- corresponds to Document.metadata
  embedding vector(768) -- 768 dimensions for approved embedding models (e.g., sentence-transformers/all-mpnet-base-v2)
);

-- Create a function to search for documents
create function match_documents (
  query_embedding vector(768),
  match_count int DEFAULT null,
  filter jsonb DEFAULT '{}'
) returns table (
  content text,
  source text,
  title text,
  similarity float
)
language plpgsql
as $$
#variable_conflict use_column
begin
  return query
  select
    left(content, 2000),
    (metadata->>'source')::text,
    (metadata->>'title')::text,
    1 - (documents.embedding <=> query_embedding) as similarity
  from documents
  where metadata @> filter
  order by documents.embedding <=> query_embedding
  limit match_count;
end;
$$;
