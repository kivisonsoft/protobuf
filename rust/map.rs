// Protocol Buffers - Google's data interchange format
// Copyright 2023 Google LLC.  All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

use crate::{
    Mut, MutProxy, Proxied, SettableValue, View, ViewProxy,
    __internal::Private,
    __runtime::{
        MapInner, MapWithBoolKeyOps, MapWithI32KeyOps, MapWithI64KeyOps, MapWithU32KeyOps,
        MapWithU64KeyOps,
    },
};
use paste::paste;
use std::marker::PhantomData;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct MapView<'a, K: ?Sized, V: ?Sized> {
    inner: MapInner<'a, K, V>,
}

impl<'a, K: ?Sized, V: ?Sized> MapView<'a, K, V> {
    pub fn from_inner(_private: Private, inner: MapInner<'a, K, V>) -> Self {
        Self { inner }
    }
}

unsafe impl<'a, K: ?Sized, V: ?Sized> Sync for MapView<'a, K, V> {}
unsafe impl<'a, K: ?Sized, V: ?Sized> Send for MapView<'a, K, V> {}

impl<'a, K: ?Sized, V: ?Sized> std::fmt::Debug for MapView<'a, K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MapView")
            .field(&std::any::type_name::<K>())
            .field(&std::any::type_name::<V>())
            .finish()
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct MapMut<'a, K: ?Sized, V: ?Sized> {
    inner: MapInner<'a, K, V>,
}

impl<'a, K: ?Sized, V: ?Sized> MapMut<'a, K, V> {
    pub fn from_inner(_private: Private, inner: MapInner<'a, K, V>) -> Self {
        Self { inner }
    }
}

unsafe impl<'a, K: ?Sized, V: ?Sized> Sync for MapMut<'a, K, V> {}

impl<'a, K: ?Sized, V: ?Sized> std::ops::Deref for MapMut<'a, K, V> {
    type Target = MapView<'a, K, V>;
    fn deref(&self) -> &Self::Target {
        // SAFETY:
        //   - `Map{View,Mut}<'a, T>` are both `#[repr(transparent)]` over `MapInner<'a,
        //     T>`.
        //   - `MapInner` is a type alias for `NonNull`.
        unsafe { &*(self as *const Self as *const MapView<'a, K, V>) }
    }
}

// This is a ZST type so we can implement `Proxied`. Users will work with
// `MapView` (`View<'_, Map>>) and `MapMut` (Mut<'_, Map>).
pub struct Map<K: ?Sized, V: ?Sized>(PhantomData<K>, PhantomData<V>);

macro_rules! impl_scalar_map_keys {
  ($(key_type $t:ty;)*) => {
      paste! { $(
        impl<V: [< MapWith $t:camel KeyOps >]> Proxied for Map<$t, V>{
          type View<'a> = MapView<'a, $t, V> where V: 'a;
          type Mut<'a> = MapMut<'a, $t, V> where V: 'a;
        }

        impl<'a, V: [< MapWith $t:camel KeyOps >]> SettableValue<Map<$t, V>> for MapView<'a, $t, V> {
          fn set_on<'b>(self, _private: Private, mut mutator: Mut<'b, Map<$t, V>>)
          where
            Map<$t, V>: 'b {
            mutator.copy_from(self);
          }
        }

        impl<'a, V: [< MapWith $t:camel KeyOps >]> ViewProxy<'a> for MapView<'a, $t, V> {
          type Proxied = Map<$t, V>;

          fn as_view(&self) -> View<'_, Self::Proxied> {
            *self
          }

          fn into_view<'shorter>(self) -> View<'shorter, Self::Proxied>
          where 'a: 'shorter,
          {
              MapView { inner: self.inner }
          }
        }

        impl<'a, V: [< MapWith $t:camel KeyOps >]> ViewProxy<'a> for MapMut<'a, $t, V> {
          type Proxied = Map<$t, V>;

          fn as_view(&self) -> View<'_, Self::Proxied> {
            **self
          }

          fn into_view<'shorter>(self) -> View<'shorter, Self::Proxied>
          where 'a: 'shorter,
          {
            *self.into_mut::<'shorter>()
          }
        }

        impl<'a, V: [< MapWith $t:camel KeyOps >]> MutProxy<'a> for MapMut<'a, $t, V> {
          fn as_mut(&mut self) -> Mut<'_, Self::Proxied> {
              MapMut { inner: self.inner }
          }

          fn into_mut<'shorter>(self) -> Mut<'shorter, Self::Proxied>
          where 'a: 'shorter,
          {
              MapMut { inner: self.inner }
          }
        }

        impl<'a, V: [< MapWith $t:camel KeyOps >]> MapView<'a, $t, V> {
          pub fn get(&self, key: $t) -> Option<V> {
            self.inner.get(key)
          }

          pub fn len(&self) -> usize {
            self.inner.size()
          }

          pub fn is_empty(&self) -> bool {
            self.len() == 0
          }
        }

        impl<'a, V: [< MapWith $t:camel KeyOps >]> MapMut<'a, $t, V> {
          pub fn insert(&mut self, key: $t, value: V) -> bool {
            self.inner.insert(key, value)
          }

          pub fn remove(&mut self, key: $t) -> Option<V> {
            self.inner.remove(key)
          }

          pub fn clear(&mut self) {
            self.inner.clear()
          }

          pub fn copy_from(&mut self, _src: MapView<'_, $t, V>) {
            todo!("implement b/28530933");
          }
        }
      )* }
  };
}

impl_scalar_map_keys!(
  key_type i32;
  key_type u32;
  key_type i64;
  key_type u64;
  key_type bool;
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::__runtime::new_map_inner;
    use googletest::prelude::*;

    #[test]
    fn test_proxied() {
        let mut map_mut = MapMut::from_inner(Private, new_map_inner());
        map_mut.insert(1, 2);
        let map_view_1 = map_mut.as_view();
        assert_that!(map_view_1.len(), eq(1));
        assert_that!(map_view_1.get(1), eq(Some(2)));

        map_mut.insert(3, 4);

        let map_view_2 = map_mut.into_view();
        assert_that!(map_view_2.len(), eq(2));
        assert_that!(map_view_2.get(3), eq(Some(4)));

        {
            let map_view_3 = map_view_2.as_view();
            assert_that!(map_view_3.is_empty(), eq(false));
        }

        let map_view_4 = map_view_2.into_view();
        assert_that!(map_view_4.is_empty(), eq(false));
    }

    #[test]
    fn test_dbg() {
        let map_view = MapView::from_inner(Private, new_map_inner());
        assert_that!(format!("{:?}", map_view), eq("MapView(\"i32\", \"i64\")"));
    }
}
