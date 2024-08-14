<!-- .vitepress/theme/MyLayout.vue -->
<script setup>
import DefaultTheme from 'vitepress/theme'
import { useData } from 'vitepress'
// import Giscus from '@giscus/vue'
// import Gitalk from '../../components/vue/Gitalk.vue'
import Gitalk from '@/components/vue/Gitalk.vue'

// https://vitepress.dev/zh/guide/extending-default-theme
const { Layout } = DefaultTheme
const pageData = useData()
</script>

<template>
  <Layout>
    <template #doc-before>
      <div class="my-last-updated">
        {{ new Date(useData().page.value.lastUpdated).toLocaleString().slice(0, -3) }}
      </div>
    </template>
    <template #doc-after>
      <div style="margin-top: 2em" />
      <Gitalk />
    </template>
  </Layout>
</template>

<style>
.my-last-updated {
  margin-bottom: 20px;
  font-style: italic;
  color: #666;
}
</style>
